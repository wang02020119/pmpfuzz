from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from pmpfuzz.capabilities import DEFAULT_CAPABILITY_SCHEMA_VERSION, capability_for_dut
from pmpfuzz.coverage_universe import load_coverage_universe
from pmpfuzz.schema import write_json
from pmpfuzz.u74_boot_chain import (
    parse_boot_chain_evidence_text,
    validate_boot_chain_policy,
    validate_runtime_boot_chain_evidence,
)
from pmpfuzz.u74_board import (
    DIRECT_U74_BOARD_CASES,
    ENGINEERING_SMOKE_VALIDATOR_PROFILE,
    is_u74_group_marker,
    build_supported_bapc_universe,
    default_u74_observation_profile,
    default_u74_board_run_manifest,
    load_json,
    parse_uart_log,
    split_round_campaign_id,
    synthesize_fake_uart_log,
    synthesize_fake_structured_uart_events,
    validate_round_artifacts,
    write_round_materialization,
)

_WORKSPACE_ROOT = Path(
    os.environ.get("PMPFUZZ_WORKSPACE", str(Path.home() / "pmpfuzz-workspace"))
).expanduser()
_ARTIFACT_ROOT = Path(os.environ.get("PMPFUZZ_ARTIFACT_ROOT", "artifacts")).expanduser()
DEFAULT_U74_OPEN_SBI_TREE = Path(
    os.environ.get("PMPFUZZ_U74_OPENSBI_TREE", str(_WORKSPACE_ROOT / "third_party" / "opensbi"))
).expanduser()
DEFAULT_U74_BOOT_ARTIFACTS_DIR = Path(
    os.environ.get("PMPFUZZ_U74_BOOT_ARTIFACTS", str(_ARTIFACT_ROOT / "u74" / "boot"))
).expanduser()
DEFAULT_U74_TOOLS_DIR = Path(
    os.environ.get("PMPFUZZ_U74_TOOLS", str(_WORKSPACE_ROOT / "u74-tools"))
).expanduser()
DEFAULT_U74_BOARD_HOST = os.environ.get("PMPFUZZ_U74_BOARD_HOST", "")
DEFAULT_U74_BOARD_USER = os.environ.get("PMPFUZZ_U74_BOARD_USER", "")
_u74_ssh_key = os.environ.get("PMPFUZZ_U74_SSH_KEY", "")
DEFAULT_U74_BOARD_SSH_KEY = Path(_u74_ssh_key).expanduser() if _u74_ssh_key else None
DEFAULT_U74_BOARD_UART_PORT = os.environ.get("PMPFUZZ_U74_UART_PORT", "")
DEFAULT_U74_BOARD_UART_BAUD = int(os.environ.get("PMPFUZZ_U74_UART_BAUD", "115200"))
DEFAULT_U74_REMOTE_BUILD_HOST = os.environ.get("PMPFUZZ_U74_REMOTE_BUILD_HOST", "")
DEFAULT_U74_REMOTE_BUILD_ROOT = os.environ.get(
    "PMPFUZZ_U74_REMOTE_BUILD_ROOT", "/tmp/pmpfuzz-u74-builds"
)
DEFAULT_U74_REMOTE_BOARD_IMAGE = "/tmp/pmpfuzz-u74-pilot-fit.img"
DEFAULT_U74_REMOTE_BOARD_INSTALL = "/tmp/install_sd_p2_probe.sh"
MIN_ELAPSED_SECONDS = 0.000001

CONTROLLER_PATCH_REL_PATHS = (
    Path("pmpfuzz/capabilities.py"),
    Path("pmpfuzz/u74_board.py"),
    Path("scripts/evaluation/campaigns/run_closed_loop_campaign.py"),
    Path("scripts/evaluation/hardware/u74/run_u74_board_round.py"),
)

BOARD_SOURCE_REL_PATHS = (
    Path("lib/sbi/sbi_init.c"),
    Path("platform/generic/starfive/jh7110.c"),
    Path("platform/generic/starfive/objects.mk"),
    Path("platform/generic/starfive/security_chain_probe.c"),
    Path("platform/generic/starfive/pmpfuzz_board_runner.c"),
    Path("platform/generic/starfive/pmpfuzz_board_generated_manifest.c"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one U74 board-feedback round")
    parser.add_argument("--dut", default="u74")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--schedule", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--variant", default="bb")
    parser.add_argument("--time-budget", default="")
    parser.add_argument("--per-case-timeout", type=int, default=30)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--record-timeline", action="store_true")
    parser.add_argument("--u74-catalog", type=Path, required=True)
    parser.add_argument("--u74-observation-profile", type=Path, default=None)
    parser.add_argument("--u74-board-patch-manifest", type=Path, default=None)
    parser.add_argument("--campaign-metadata", type=Path, default=None)
    parser.add_argument("--capability-fingerprint", default="")
    parser.add_argument("--u74-supported-bapc-universe", type=Path, default=None)
    parser.add_argument("--u74-supported-bapc-universe-sha256", default="")
    parser.add_argument("--u74-supported-bapc-universe-file-sha256", default="")
    parser.add_argument("--validator-profile", default=ENGINEERING_SMOKE_VALIDATOR_PROFILE)
    parser.add_argument("--u74-generated-round-manifest", type=Path, default=None)
    parser.add_argument("--u74-boot-chain-policy", type=Path, default=None)
    parser.add_argument("--mode", choices=("real", "fake"), default="real")
    parser.add_argument("--prebuilt-fit-path", type=Path, default=None)
    parser.add_argument("--u74-opensbi-tree", type=Path, default=DEFAULT_U74_OPEN_SBI_TREE)
    parser.add_argument("--u74-boot-artifacts-dir", type=Path, default=DEFAULT_U74_BOOT_ARTIFACTS_DIR)
    parser.add_argument("--u74-tools-dir", type=Path, default=DEFAULT_U74_TOOLS_DIR)
    parser.add_argument("--board-ssh-user", default=DEFAULT_U74_BOARD_USER)
    parser.add_argument("--board-ssh-host", default=DEFAULT_U74_BOARD_HOST)
    parser.add_argument("--board-ssh-key", type=Path, default=DEFAULT_U74_BOARD_SSH_KEY)
    parser.add_argument("--board-sudo-password", default=os.environ.get("VF2_SUDO_PASSWORD", ""))
    parser.add_argument("--board-uart-port", default=DEFAULT_U74_BOARD_UART_PORT)
    parser.add_argument("--board-uart-baud", type=int, default=DEFAULT_U74_BOARD_UART_BAUD)
    parser.add_argument("--capture-seconds", type=int, default=180)
    parser.add_argument("--capture-wait-timeout-seconds", type=int, default=900)
    parser.add_argument("--board-reboot-over-ssh", action="store_true",
                        help="Trigger a board reboot via SSH (sudo reboot) before UART capture "
                             "instead of requiring a manual cold power cycle.")
    parser.add_argument("--remote-build-host", default=DEFAULT_U74_REMOTE_BUILD_HOST)
    parser.add_argument("--remote-build-root", default=DEFAULT_U74_REMOTE_BUILD_ROOT)
    return parser


def _manifest_sha256(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _load_schedule(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="ascii"))
    return [dict(item) for item in (data.get("entries") or []) if isinstance(item, dict)]


def _lowered_cases_from_schedule(schedule_entries: list[dict]) -> list[dict[str, Any]]:
    """Extract lowered board-case payloads from the schedule's ``lowering`` fields.

    Every lowered U74 scenario entry carries a fully-materialized ``lowering``
    object with the same schema as a generated-manifest lowered case (probe
    address, access, expected trap, PMP entries, ...). The board firmware's
    lowered case loop is only rendered when ``lowered_cases`` is present in the
    manifest payload, so building it here keeps runs that do not pass a frozen
    generated-round-manifest file from silently generating a manifest-only
    (no-case-loop) firmware image.
    """
    return [dict(item["lowering"]) for item in schedule_entries if item.get("lowering")]


def _load_observation_profile(path: Path | None) -> dict:
    if path is None:
        return default_u74_observation_profile()
    return load_json(path)


def _load_board_patch_manifest(path: Path | None) -> dict:
    if path is None:
        return {}
    return load_json(path)


def _load_campaign_metadata(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return load_json(path)


def _load_generated_round_manifest(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return load_json(path)


def _load_boot_chain_policy(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return load_json(path)


def _default_capability_fingerprint(observation_profile: dict[str, Any]) -> str:
    raw = json.dumps(
        {
            "dut": "u74",
            "finish_protocol": "uart-log",
            "diagnostic_depth": "observation-only",
            "observation_profile_id": str(observation_profile.get("observation_profile_id") or ""),
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _elapsed_seconds(start: float, end: float | None = None) -> float:
    elapsed = float((time.perf_counter() if end is None else end) - start)
    return max(round(elapsed, 6), MIN_ELAPSED_SECONDS)


def _elapsed_value(value: object, *, fallback: float) -> float:
    try:
        elapsed = float(value)
    except (TypeError, ValueError):
        return fallback
    if elapsed <= 0.0:
        return fallback
    return round(elapsed, 6)


def _resolve_round_validation_context(
    *,
    args: argparse.Namespace,
    campaign_id: str,
    round_id: str,
    observation_profile: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None, Path | None]:
    campaign_metadata = _load_campaign_metadata(args.campaign_metadata)
    if campaign_metadata:
        metadata_campaign_id = str(campaign_metadata.get("campaign_id") or "")
        if metadata_campaign_id and metadata_campaign_id != campaign_id:
            raise ValueError(
                f"campaign metadata mismatch: expected campaign_id={campaign_id}, got {metadata_campaign_id}"
            )
    metadata_identity = dict(campaign_metadata.get("u74_round_identity") or {})
    capability_fingerprint = str(
        args.capability_fingerprint
        or metadata_identity.get("capability_fingerprint")
        or campaign_metadata.get("capability_fingerprint")
        or _default_capability_fingerprint(observation_profile)
    )

    universe_path = args.u74_supported_bapc_universe
    if universe_path is None and args.campaign_metadata is not None:
        rel = str(
            metadata_identity.get("supported_bapc_universe_file")
            or (campaign_metadata.get("coverage_universe_files") or {}).get("bapc")
            or ""
        )
        if rel:
            universe_path = (args.campaign_metadata.parent.parent / rel).resolve()
    expected_universe_sha256 = str(
        args.u74_supported_bapc_universe_sha256
        or metadata_identity.get("supported_bapc_universe_embedded_sha256")
        or (campaign_metadata.get("coverage_universe_hashes") or {}).get("bapc")
        or ""
    )
    expected_universe_file_sha256 = str(
        args.u74_supported_bapc_universe_file_sha256
        or metadata_identity.get("supported_bapc_universe_file_sha256")
        or ""
    )
    validator_profile = str(
        args.validator_profile
        or metadata_identity.get("validator_profile")
        or ENGINEERING_SMOKE_VALIDATOR_PROFILE
    )

    frozen_universe = None
    if universe_path is not None:
        frozen_universe = load_coverage_universe(universe_path)
        actual_universe_file_sha256 = _sha256_file(universe_path)
        if expected_universe_sha256 and str(frozen_universe.get("sha256") or "") != expected_universe_sha256:
            raise ValueError(
                "frozen U74 supported BAPC universe sha256 mismatch: "
                f"expected {expected_universe_sha256}, got {frozen_universe.get('sha256')}"
            )
        if expected_universe_file_sha256 and actual_universe_file_sha256 != expected_universe_file_sha256:
            raise ValueError(
                "frozen U74 supported BAPC universe file sha256 mismatch: "
                f"expected {expected_universe_file_sha256}, got {actual_universe_file_sha256}"
            )
        if str(frozen_universe.get("capability_fingerprint") or "") != capability_fingerprint:
            raise ValueError(
                "frozen U74 supported BAPC universe capability_fingerprint mismatch: "
                f"expected {capability_fingerprint}, got {frozen_universe.get('capability_fingerprint')}"
            )
        observation_profile_id = str(observation_profile.get("observation_profile_id") or "")
        if observation_profile_id and str(frozen_universe.get("observation_profile_id") or "") not in {"", observation_profile_id}:
            raise ValueError(
                "frozen U74 supported BAPC universe observation_profile_id mismatch: "
                f"expected {observation_profile_id}, got {frozen_universe.get('observation_profile_id')}"
            )
        expected_universe_sha256 = str(frozen_universe.get("sha256") or expected_universe_sha256)
        expected_universe_file_sha256 = actual_universe_file_sha256

    validation_context = {
        "campaign_id": campaign_id,
        "round_id": round_id,
        "validator_profile": validator_profile,
        "campaign_metadata_path": str(args.campaign_metadata) if args.campaign_metadata is not None else "",
        "capability_fingerprint": capability_fingerprint,
        "supported_bapc_universe_sha256": expected_universe_sha256,
        "supported_bapc_universe_file_sha256": expected_universe_file_sha256,
        "supported_bapc_universe_path": str(universe_path) if universe_path is not None else "",
        "observation_profile_id": str(observation_profile.get("observation_profile_id") or ""),
    }
    return validation_context, frozen_universe, universe_path


def _sha256_named_files(paths: list[Path], *, relative_to: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: str(item).lower()):
        rel = path.resolve().relative_to(relative_to.resolve())
        digest.update(str(rel).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _c_literal(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _controller_patch_paths(controller_root: Path) -> list[Path]:
    return [controller_root / rel for rel in CONTROLLER_PATCH_REL_PATHS]


def _board_source_paths(source_root: Path) -> list[Path]:
    return [source_root / rel for rel in BOARD_SOURCE_REL_PATHS]


def validate_direct_board_case_selection(schedule_entries: list[dict]) -> None:
    unsupported = sorted(
        {
            str(entry.get("name") or "")
            for entry in schedule_entries
            if not entry.get("scenario_spec")
            and not entry.get("lowering")
            and str(entry.get("name") or "") not in DIRECT_U74_BOARD_CASES
            and not is_u74_group_marker(str(entry.get("name") or ""))
        }
    )
    if unsupported:
        raise ValueError(
            "Unsupported U74 board-selected cases: " + ", ".join(unsupported)
        )


def _render_lowered_pmp_entries(entries: list[dict[str, Any]]) -> str:
    if not entries or len(entries) > 2:
        raise ValueError("lowered U74 scenario cases require one or two PMP entries")
    rendered = []
    for entry in entries:
        rendered.append(
            "{ "
            f"{int(entry['prot'])}UL, "
            f"0x{int(entry['addr']):x}UL, "
            f"{int(entry['log2len'])}UL "
            "}"
        )
    while len(rendered) < 2:
        rendered.append("{ 0UL, 0UL, 0UL }")
    return "{ " + ", ".join(rendered) + " }"


def _render_lowered_case_table(lowered_cases: list[dict[str, Any]]) -> str:
    # Option A locked protocol: cases that install a locked PMP entry are moved
    # to the end of the round so their irreversible entries do not contaminate
    # later cases; the round resets once after the locked batch.
    def _case_is_locked(case: dict[str, Any]) -> bool:
        return any(
            bool(int((entry.get("prot") or 0)) & 0x80)
            for entry in (case.get("pmp_entries") or [])
        )

    lowered_cases = sorted(
        lowered_cases, key=lambda case: 1 if _case_is_locked(case) else 0
    )
    lines = []
    for case in lowered_cases:
        access = str(case.get("access") or "")
        if access not in {"load", "store", "fetch"}:
            raise ValueError(f"unsupported lowered U74 access: {access}")
        entries = [dict(item) for item in (case.get("pmp_entries") or [])]
        expected_trap = 0 if bool(case.get("expected_allowed")) else 1
        expected_cause = int(case.get("expected_cause") or 0)
        access_code = {"load": 0, "store": 1, "fetch": 2}[access]
        satp = int(case.get("satp") or 0)
        va = int(case.get("va") or case.get("probe_pa") or 0)
        pte_flags = int(case.get("pte_flags") or 0)
        lines.append(
            "\t{ "
            f"{_c_literal(str(case.get('name') or ''))}, "
            f"{_c_literal(str(case.get('profile') or ''))}, "
            f"{_c_literal(str(case.get('scenario_hash') or ''))}, "
            f"0x{int(case['probe_pa']):x}UL, "
            f"{int(case['mpp'])}UL, "
            f"{expected_cause}UL, "
            f"0x{int(case.get('store_value') or 0):x}UL, "
            f"{access_code}U, "
            f"{expected_trap}U, "
            f"0x{satp:x}UL, "
            f"0x{va:x}UL, "
            f"0x{pte_flags:x}UL, "
            f"{len(entries)}U, "
            f"{_render_lowered_pmp_entries(entries)} "
            "},"
        )
    return "\n".join(lines)


def _render_lowered_board_manifest_c(
    *,
    campaign_id: str,
    round_id: str,
    manifest_sha256: str,
    selected_cases: list[str],
    lowered_cases: list[dict[str, Any]],
) -> str:
    case_lines = "\n".join(f"\t{_c_literal(case)}," for case in selected_cases) or "\tNULL,"
    selected_count = len(selected_cases)
    lowered_table = _render_lowered_case_table(lowered_cases)
    return (
        "/*\n"
        " * SPDX-License-Identifier: BSD-2-Clause\n"
        " *\n"
        " * Auto-generated scenario-lowered U74 manifest by run_u74_board_round.py.\n"
        " */\n\n"
        "#include <sbi/riscv_asm.h>\n"
        "#include <sbi/riscv_encoding.h>\n"
        "#include <sbi/sbi_console.h>\n"
        "#include <sbi/sbi_csr_detect.h>\n"
        "#include <sbi/sbi_hart.h>\n"
        "#include <sbi/sbi_scratch.h>\n"
        "#include <sbi/sbi_trap.h>\n"
        "#include <sbi/sbi_types.h>\n\n"
        '#define PF_TAG "[pmpfuzz] "\n'
        "#define PF_LOWERED_SENTINEL 0x4d505046555a5a31UL\n"
        "#define PF_LOWERED_ACCESS_LOAD 0U\n"
        "#define PF_LOWERED_ACCESS_STORE 1U\n"
        "#define PF_LOWERED_ACCESS_FETCH 2U\n\n"
        "void pmpfuzz_lowered_fetch_record(const char *name, const char *profile,\n"
        "\t\t\t\t      ulong entry, ulong mpp, ulong satp,\n"
        "\t\t\t\t      ulong expected_cause, int expected_trap);\n"
        "int pmpfuzz_lowered_sv39_begin(ulong va, ulong pa, ulong flags,\n"
        "\t\t\t\t       ulong *old_satp_out);\n"
        "void pmpfuzz_lowered_sv39_end(ulong old_satp);\n\n"
        "struct pmpfuzz_lowered_pmp_entry {\n"
        "\tulong prot;\n"
        "\tulong addr;\n"
        "\tulong log2len;\n"
        "};\n\n"
        "struct pmpfuzz_lowered_case {\n"
        "\tconst char *name;\n"
        "\tconst char *profile;\n"
        "\tconst char *scenario_hash;\n"
        "\tulong probe_pa;\n"
        "\tulong mpp;\n"
        "\tulong expected_cause;\n"
        "\tulong store_value;\n"
        "\tunsigned int access;\n"
        "\tunsigned int expected_trap;\n"
        "\tulong satp;\n"
        "\tulong va;\n"
        "\tulong pte_flags;\n"
        "\tunsigned int entry_count;\n"
        "\tstruct pmpfuzz_lowered_pmp_entry entries[2];\n"
        "};\n\n"
        "void pmpfuzz_board_record_generated_result(const char *status) __attribute__((weak));\n\n"
        "static void pmpfuzz_lowered_count_status(const char *status)\n"
        "{\n"
        "\tif (pmpfuzz_board_record_generated_result)\n"
        "\t\tpmpfuzz_board_record_generated_result(status);\n"
        "}\n\n"
        "static const char *const pmpfuzz_selected_cases[] = {\n"
        f"{case_lines}\n"
        "};\n\n"
        "static const struct pmpfuzz_lowered_case pmpfuzz_lowered_cases[] = {\n"
        f"{lowered_table}\n"
        "};\n\n"
        "static int pmpfuzz_streq(const char *lhs, const char *rhs)\n"
        "{\n"
        "\tif (!lhs || !rhs)\n"
        "\t\treturn 0;\n"
        "\twhile (*lhs && *rhs && *lhs == *rhs) {\n"
        "\t\tlhs++;\n"
        "\t\trhs++;\n"
        "\t}\n"
        "\treturn *lhs == *rhs;\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_campaign_id(void)\n"
        "{\n"
        f"\treturn {_c_literal(campaign_id)};\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_round_id(void)\n"
        "{\n"
        f"\treturn {_c_literal(round_id)};\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_sha256(void)\n"
        "{\n"
        f"\treturn {_c_literal(manifest_sha256)};\n"
        "}\n\n"
        "ulong pmpfuzz_board_manifest_case_count(void)\n"
        "{\n"
        f"\treturn {selected_count}UL;\n"
        "}\n\n"
        "int pmpfuzz_board_case_selected(const char *name)\n"
        "{\n"
        "\tunsigned long index;\n\n"
        "\tif (!name)\n"
        "\t\treturn 0;\n"
        f"\tfor (index = 0; index < {selected_count}UL; index++) {{\n"
        "\t\tif (pmpfuzz_streq(name, pmpfuzz_selected_cases[index]))\n"
        "\t\t\treturn 1;\n"
        "\t}\n"
        "\treturn 0;\n"
        "}\n\n"
        "static const char *pmpfuzz_lowered_trap_name(ulong cause)\n"
        "{\n"
        "\tswitch (cause) {\n"
        "\tcase CAUSE_MISALIGNED_LOAD:\n"
        "\t\treturn \"misaligned_load\";\n"
        "\tcase CAUSE_LOAD_ACCESS:\n"
        "\t\treturn \"load_access\";\n"
        "\tcase CAUSE_MISALIGNED_STORE:\n"
        "\t\treturn \"misaligned_store\";\n"
        "\tcase CAUSE_STORE_ACCESS:\n"
        "\t\treturn \"store_access\";\n"
        "\tcase 0:\n"
        "\t\treturn \"none\";\n"
        "\tdefault:\n"
        "\t\treturn \"unknown\";\n"
        "\t}\n"
        "}\n\n"
        "static void pmpfuzz_lowered_fence_rw_rw(void)\n"
        "{\n"
        "\t__asm__ __volatile__(\"fence rw,rw\" ::: \"memory\");\n"
        "}\n\n"
        "static u32 pmpfuzz_lowered_load32_mprv(const u32 *addr, ulong mpp,\n"
        "\t\t\t\t\t\t struct sbi_trap_info *trap)\n"
        "{\n"
        "\tregister ulong tinfo asm(\"a3\") = (ulong)trap;\n"
        "\tregister ulong ttmp asm(\"a4\");\n"
        "\tregister ulong mtvec = sbi_hart_expected_trap_addr();\n"
        "\tregister ulong old_mstatus = csr_read(CSR_MSTATUS);\n"
        "\tregister u32 ret = 0;\n"
        "\tregister ulong new_mstatus =\n"
        "\t\t(old_mstatus & ~(MSTATUS_MPP | MSTATUS_SUM | MSTATUS_MXR)) |\n"
        "\t\tMSTATUS_MPRV | (mpp << MSTATUS_MPP_SHIFT);\n\n"
        "\ttrap->cause = 0;\n"
        "\tasm volatile(\n"
        "\t\t\"add %[ttmp], %[tinfo], zero\\n\"\n"
        "\t\t\"csrrw %[mtvec], \" STR(CSR_MTVEC) \", %[mtvec]\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MSTATUS) \", %[new_mstatus]\\n\"\n"
        "\t\t\".option push\\n\"\n"
        "\t\t\".option norvc\\n\"\n"
        "\t\t\"lw %[ret], 0(%[addr])\\n\"\n"
        "\t\t\".option pop\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MSTATUS) \", %[old_mstatus]\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MTVEC) \", %[mtvec]\"\n"
        "\t    : [mtvec] \"+&r\"(mtvec), [tinfo] \"+&r\"(tinfo),\n"
        "\t      [ttmp] \"+&r\"(ttmp), [ret] \"=&r\"(ret)\n"
        "\t    : [addr] \"r\"(addr), [new_mstatus] \"r\"(new_mstatus),\n"
        "\t      [old_mstatus] \"r\"(old_mstatus)\n"
        "\t    : \"memory\");\n\n"
        "\tcsr_write(CSR_MSTATUS, old_mstatus);\n"
        "\treturn ret;\n"
        "}\n\n"
        "static void pmpfuzz_lowered_store32_mprv(u32 *addr, u32 val,\n"
        "\t\t\t\t\t\t  ulong mpp, struct sbi_trap_info *trap)\n"
        "{\n"
        "\tregister ulong tinfo asm(\"a3\") = (ulong)trap;\n"
        "\tregister ulong ttmp asm(\"a4\");\n"
        "\tregister ulong mtvec = sbi_hart_expected_trap_addr();\n"
        "\tregister ulong old_mstatus = csr_read(CSR_MSTATUS);\n"
        "\tregister ulong new_mstatus =\n"
        "\t\t(old_mstatus & ~(MSTATUS_MPP | MSTATUS_SUM | MSTATUS_MXR)) |\n"
        "\t\tMSTATUS_MPRV | (mpp << MSTATUS_MPP_SHIFT);\n\n"
        "\ttrap->cause = 0;\n"
        "\tasm volatile(\n"
        "\t\t\"add %[ttmp], %[tinfo], zero\\n\"\n"
        "\t\t\"csrrw %[mtvec], \" STR(CSR_MTVEC) \", %[mtvec]\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MSTATUS) \", %[new_mstatus]\\n\"\n"
        "\t\t\".option push\\n\"\n"
        "\t\t\".option norvc\\n\"\n"
        "\t\t\"sw %[val], 0(%[addr])\\n\"\n"
        "\t\t\".option pop\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MSTATUS) \", %[old_mstatus]\\n\"\n"
        "\t\t\"csrw \" STR(CSR_MTVEC) \", %[mtvec]\"\n"
        "\t    : [mtvec] \"+&r\"(mtvec), [tinfo] \"+&r\"(tinfo),\n"
        "\t      [ttmp] \"+&r\"(ttmp)\n"
        "\t    : [addr] \"r\"(addr), [val] \"r\"(val),\n"
        "\t      [new_mstatus] \"r\"(new_mstatus),\n"
        "\t      [old_mstatus] \"r\"(old_mstatus)\n"
        "\t    : \"memory\");\n\n"
        "\tcsr_write(CSR_MSTATUS, old_mstatus);\n"
        "}\n\n"
        "static int pmpfuzz_lowered_safe_store32(ulong pa, u32 val)\n"
        "{\n"
        "\tstruct sbi_trap_info trap = { 0 };\n\n"
        "\tpmpfuzz_lowered_store32_mprv((u32 *)pa, val, PRV_M, &trap);\n"
        "\treturn trap.cause ? -1 : 0;\n"
        "}\n\n"
        "static int pmpfuzz_lowered_choose_entries(unsigned int *entries,\n"
        "\t\t\t\t\t\t unsigned int need)\n"
        "{\n"
        "\tstruct sbi_scratch *scratch = sbi_scratch_thishart_ptr();\n"
        "\tunsigned int count = sbi_hart_pmp_count(scratch);\n"
        "\tunsigned int i, j;\n"
        "\tunsigned long prot, addr, log2len;\n"
        "\tunsigned long cand_prot, cand_addr, cand_log2len;\n\n"
        "\tif (!entries || !need || need > 2)\n"
        "\t\treturn -1;\n"
        "\tfor (i = need; i < count; i++) {\n"
        "\t\tif (pmp_get(i, &prot, &addr, &log2len))\n"
        "\t\t\tcontinue;\n"
        "\t\tif (!(prot & PMP_A) || addr != 0 || log2len < 34)\n"
        "\t\t\tcontinue;\n"
        "\t\tif (!((prot & PMP_R) && (prot & PMP_W) && (prot & PMP_X)))\n"
        "\t\t\tcontinue;\n"
        "\t\tfor (j = 0; j < need; j++) {\n"
        "\t\t\tif (pmp_get(i - need + j, &cand_prot, &cand_addr,\n"
        "\t\t\t\t    &cand_log2len))\n"
        "\t\t\t\tbreak;\n"
        "\t\t\tif (cand_prot & PMP_L)\n"
        "\t\t\t\tbreak;\n"
        "\t\t}\n"
        "\t\tif (j == need) {\n"
        "\t\t\tfor (j = 0; j < need; j++)\n"
        "\t\t\t\tentries[j] = i - need + j;\n"
        "\t\t\treturn 0;\n"
        "\t\t}\n"
        "\t}\n"
        "\tfor (i = 0; i + need <= count; i++) {\n"
        "\t\tfor (j = 0; j < need; j++) {\n"
        "\t\t\tif (pmp_get(i + j, &cand_prot, &cand_addr,\n"
        "\t\t\t\t    &cand_log2len))\n"
        "\t\t\t\tbreak;\n"
        "\t\t\tif ((cand_prot & PMP_L) || (cand_prot & PMP_A))\n"
        "\t\t\t\tbreak;\n"
        "\t\t}\n"
        "\t\tif (j == need) {\n"
        "\t\t\tfor (j = 0; j < need; j++)\n"
        "\t\t\t\tentries[j] = i + j;\n"
        "\t\t\treturn 0;\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn -1;\n"
        "}\n\n"
        "static void pmpfuzz_lowered_restore_entry(unsigned int entry,\n"
        "\t\t\t\t\t\t unsigned long prot,\n"
        "\t\t\t\t\t\t unsigned long addr,\n"
        "\t\t\t\t\t\t unsigned long log2len)\n"
        "{\n"
        "\tunsigned long cur_prot, cur_addr, cur_log2len;\n"
        "\tif (!pmp_get(entry, &cur_prot, &cur_addr, &cur_log2len) &&\n"
        "\t    (cur_prot & PMP_L))\n"
        "\t\treturn; /* locked entry cannot be restored; round resets afterwards */\n"
        "\tif (prot & PMP_A)\n"
        "\t\tpmp_set(entry, prot, addr, log2len);\n"
        "\telse\n"
        "\t\tpmp_disable(entry);\n"
        "\tpmpfuzz_lowered_fence_rw_rw();\n"
        "}\n\n"
        "static void pmpfuzz_lowered_csr_write_pmpaddr(unsigned int entry,\n"
        "\t\t\t\t\t\t      unsigned long val)\n"
        "{\n"
        "\tswitch (entry) {\n"
        + "".join(
            f"\tcase {i}: csr_write(CSR_PMPADDR{i}, val); break;\n"
            for i in range(16)
        )
        + "\tdefault: break;\n"
        "\t}\n"
        "}\n\n"
        "static unsigned int pmpfuzz_lowered_pmpcfg_byte_shift(unsigned int entry)\n"
        "{\n"
        "#if __riscv_xlen == 64\n"
        "\treturn (entry & 7) << 3;\n"
        "#else\n"
        "\treturn (entry & 3) << 3;\n"
        "#endif\n"
        "}\n\n"
        "static unsigned long pmpfuzz_lowered_csr_read_pmpcfg(unsigned int entry)\n"
        "{\n"
        "\t/* RV64 packs 8 PMP entries per 64-bit pmpcfg register and only\n"
        "\t * implements pmpcfg0 (0x3a0) and pmpcfg2 (0x3a2); RV32 uses four\n"
        "\t * 32-bit pmpcfg0..3. Mirror the pmpcfg_csr selection in\n"
        "\t * lib/sbi/riscv_asm.c so the lowered TOR path never touches the\n"
        "\t * reserved pmpcfg1/pmpcfg3 CSR numbers on RV64. */\n"
        "\tswitch (entry >> 2) {\n"
        "#if __riscv_xlen == 64\n"
        "\tcase 0:\n"
        "\tcase 1:\n"
        "\t\treturn csr_read(CSR_PMPCFG0);\n"
        "\tcase 2:\n"
        "\tcase 3:\n"
        "\t\treturn csr_read(CSR_PMPCFG2);\n"
        "#else\n"
        "\tcase 0:\n"
        "\t\treturn csr_read(CSR_PMPCFG0);\n"
        "\tcase 1:\n"
        "\t\treturn csr_read(CSR_PMPCFG1);\n"
        "\tcase 2:\n"
        "\t\treturn csr_read(CSR_PMPCFG2);\n"
        "\tcase 3:\n"
        "\t\treturn csr_read(CSR_PMPCFG3);\n"
        "#endif\n"
        "\tdefault:\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "}\n\n"
        "static void pmpfuzz_lowered_csr_write_pmpcfg(unsigned int entry,\n"
        "\t\t\t\t\t      unsigned long val)\n"
        "{\n"
        "\t/* Same RV64/RV32 pmpcfg register selection as csr_read above. */\n"
        "\tswitch (entry >> 2) {\n"
        "#if __riscv_xlen == 64\n"
        "\tcase 0:\n"
        "\tcase 1:\n"
        "\t\tcsr_write(CSR_PMPCFG0, val);\n"
        "\t\tbreak;\n"
        "\tcase 2:\n"
        "\tcase 3:\n"
        "\t\tcsr_write(CSR_PMPCFG2, val);\n"
        "\t\tbreak;\n"
        "#else\n"
        "\tcase 0:\n"
        "\t\tcsr_write(CSR_PMPCFG0, val);\n"
        "\t\tbreak;\n"
        "\tcase 1:\n"
        "\t\tcsr_write(CSR_PMPCFG1, val);\n"
        "\t\tbreak;\n"
        "\tcase 2:\n"
        "\t\tcsr_write(CSR_PMPCFG2, val);\n"
        "\t\tbreak;\n"
        "\tcase 3:\n"
        "\t\tcsr_write(CSR_PMPCFG3, val);\n"
        "\t\tbreak;\n"
        "#endif\n"
        "\tdefault:\n"
        "\t\tbreak;\n"
        "\t}\n"
        "}\n\n"
        "static unsigned long pmpfuzz_lowered_csr_read_pmpaddr(unsigned int entry)\n"
        "{\n"
        "\tswitch (entry) {\n"
        + "".join(
            f"\tcase {i}: return csr_read(CSR_PMPADDR{i});\n"
            for i in range(16)
        )
        + "\tdefault: return 0;\n"
        "\t}\n"
        "}\n\n"
        "static void pmpfuzz_lowered_restore_case(unsigned int *entries,\n"
        "\t\t\t\t\t      unsigned long *old_prot,\n"
        "\t\t\t\t\t      unsigned long *old_addr,\n"
        "\t\t\t\t\t      unsigned long *old_log2len,\n"
        "\t\t\t\t\t      unsigned long *old_prev_pmpaddr,\n"
        "\t\t\t\t\t      const struct pmpfuzz_lowered_case *tc)\n"
        "{\n"
        "\tunsigned int i;\n"
        "\tfor (i = tc->entry_count; i > 0; i--) {\n"
        "\t\tunsigned int e = entries[i - 1];\n"
        "\t\t/* TOR lowered pmpaddr[e-1] to the range start; put it back. */\n"
        "\t\tif (e > 0 && (tc->entries[i - 1].prot & PMP_A) == 0x08)\n"
        "\t\t\tpmpfuzz_lowered_csr_write_pmpaddr(e - 1,\n"
        "\t\t\t\t\t\t\t  old_prev_pmpaddr[i - 1]);\n"
        "\t\tpmpfuzz_lowered_restore_entry(e, old_prot[i - 1],\n"
        "\t\t\t\t\t      old_addr[i - 1], old_log2len[i - 1]);\n"
        "\t}\n"
        "}\n\n"
        "static int pmpfuzz_lowered_install_entry(unsigned int entry,\n"
        "\t\t\t\t\t\t unsigned long prot,\n"
        "\t\t\t\t\t\t unsigned long addr,\n"
        "\t\t\t\t\t\t unsigned long log2len)\n"
        "{\n"
        "\tif ((prot & PMP_A) == 0x08) {\n"
        "\t\t/* TOR: addr is the lower bound, upper = addr + 2^(log2len+1).\n"
        "\t\t * OpenSBI pmp_set() derives NA4/NAPOT from log2len and cannot\n"
        "\t\t * encode TOR, so write the pmpaddr pair and patch the pmpcfg\n"
        "\t\t * byte explicitly (compile-time CSR constants via switch). */\n"
        "\t\tunsigned long upper = addr + (1UL << (log2len + 1));\n"
        "\t\tunsigned long cfg = 0;\n"
        "\t\tunsigned int byte_shift = pmpfuzz_lowered_pmpcfg_byte_shift(entry);\n"
        "\t\tif (entry > 0)\n"
        "\t\t\tpmpfuzz_lowered_csr_write_pmpaddr(entry - 1, addr >> 2);\n"
        "\t\tpmpfuzz_lowered_csr_write_pmpaddr(entry, upper >> 2);\n"
        "\t\tcfg = pmpfuzz_lowered_csr_read_pmpcfg(entry);\n"
        "\t\tcfg &= ~(0xFFUL << byte_shift);\n"
        "\t\tcfg |= (prot & 0xFFUL) << byte_shift;\n"
        "\t\tpmpfuzz_lowered_csr_write_pmpcfg(entry, cfg);\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "\tif (prot & PMP_A)\n"
        "\t\treturn pmp_set(entry, prot, addr, log2len);\n"
        "\tpmp_disable(entry);\n"
        "\treturn 0;\n"
        "}\n\n"
        "static const char *pmpfuzz_lowered_op(unsigned int access)\n"
        "{\n"
        "\tif (access == PF_LOWERED_ACCESS_STORE)\n"
        "\t\treturn \"store\";\n"
        "\tif (access == PF_LOWERED_ACCESS_FETCH)\n"
        "\t\treturn \"fetch\";\n"
        "\treturn \"load\";\n"
        "}\n\n"
        "static void pmpfuzz_lowered_record_skip(const struct pmpfuzz_lowered_case *tc,\n"
        "\t\t\t\t\t\t const char *reason)\n"
        "{\n"
        "\tpmpfuzz_lowered_count_status(\"skip\");\n"
        "\tsbi_printf(PF_TAG\n"
        "\t\t   \"case=%s profile=%s op=%s addr=0x%lx mpp=%lu satp=0x0 result=skip cause=0x0 trap_name=none tval=0x0 expected=%s expected_cause=0x%lx status=skip reason=%s scenario_hash=%s\\n\",\n"
        "\t\t   tc->name, tc->profile, pmpfuzz_lowered_op(tc->access),\n"
        "\t\t   tc->probe_pa, tc->mpp,\n"
        "\t\t   tc->expected_trap ? \"trap\" : \"allow\",\n"
        "\t\t   tc->expected_cause, reason, tc->scenario_hash);\n"
        "}\n\n"
        "static void pmpfuzz_lowered_record_load(const struct pmpfuzz_lowered_case *tc,\n"
        "\t\t\t\t\t\t const struct sbi_trap_info *trap,\n"
        "\t\t\t\t\t\t ulong value)\n"
        "{\n"
        "\tint ok = tc->expected_trap ? trap->cause == tc->expected_cause : !trap->cause;\n\n"
        "\tpmpfuzz_lowered_count_status(ok ? \"pass\" : \"fail\");\n"
        "\tsbi_printf(PF_TAG\n"
        "\t\t   \"case=%s profile=%s op=load addr=0x%lx mpp=%lu satp=0x%lx result=%s cause=0x%lx trap_name=%s tval=0x%lx value=0x%lx expected=%s expected_cause=0x%lx status=%s scenario_hash=%s\\n\",\n"
        "\t\t   tc->name, tc->profile, tc->probe_pa, tc->mpp, tc->satp,\n"
        "\t\t   trap->cause ? \"trap\" : \"allow\", trap->cause,\n"
        "\t\t   pmpfuzz_lowered_trap_name(trap->cause), trap->tval, value,\n"
        "\t\t   tc->expected_trap ? \"trap\" : \"allow\",\n"
        "\t\t   tc->expected_cause, ok ? \"pass\" : \"fail\",\n"
        "\t\t   tc->scenario_hash);\n"
        "}\n\n"
        "static void pmpfuzz_lowered_record_store(const struct pmpfuzz_lowered_case *tc,\n"
        "\t\t\t\t\t\t  const struct sbi_trap_info *trap,\n"
        "\t\t\t\t\t\t  ulong before, ulong after)\n"
        "{\n"
        "\tint ok = tc->expected_trap ?\n"
        "\t\ttrap->cause == tc->expected_cause && after == before :\n"
        "\t\t!trap->cause && after == tc->store_value;\n\n"
        "\tpmpfuzz_lowered_count_status(ok ? \"pass\" : \"fail\");\n"
        "\tsbi_printf(PF_TAG\n"
        "\t\t   \"case=%s profile=%s op=store addr=0x%lx mpp=%lu satp=0x%lx result=%s cause=0x%lx trap_name=%s tval=0x%lx before=0x%lx after=0x%lx target=0x%lx expected=%s expected_cause=0x%lx side_effect=%d status=%s scenario_hash=%s\\n\",\n"
        "\t\t   tc->name, tc->profile, tc->probe_pa, tc->mpp, tc->satp,\n"
        "\t\t   trap->cause ? \"trap\" : \"allow\", trap->cause,\n"
        "\t\t   pmpfuzz_lowered_trap_name(trap->cause), trap->tval,\n"
        "\t\t   before, after, tc->store_value,\n"
        "\t\t   tc->expected_trap ? \"trap\" : \"allow\",\n"
        "\t\t   tc->expected_cause,\n"
        "\t\t   tc->expected_trap ? after != before : after != tc->store_value,\n"
        "\t\t   ok ? \"pass\" : \"fail\", tc->scenario_hash);\n"
        "}\n\n"
        "static void pmpfuzz_lowered_run_one(const struct pmpfuzz_lowered_case *tc,\n"
        "\t\t\t\t\t      ulong ordinal)\n"
        "{\n"
        "\tunsigned int entries[2] = { 0, 0 };\n"
        "\tunsigned int i;\n"
        "\tunsigned long old_prot[2] = { 0, 0 };\n"
        "\tunsigned long old_addr[2] = { 0, 0 };\n"
        "\tunsigned long old_log2len[2] = { 0, 0 };\n"
        "\tunsigned long old_prev_pmpaddr[2] = { 0, 0 };\n"
        "\tulong old_satp = 0;\n"
        "\tulong probe_addr = tc->probe_pa;\n"
        "\tstruct sbi_trap_info trap = { 0 };\n"
        "\tu32 sentinel = (u32)(PF_LOWERED_SENTINEL + ordinal);\n"
        "\tulong before = 0, after = 0, value = 0;\n"
        "\tint is_sv39 = (tc->satp != 0);\n"
        "\tint is_fetch = (tc->access == PF_LOWERED_ACCESS_FETCH);\n\n"
        "\tif (!is_fetch) {\n"
        "\t\tif (pmpfuzz_lowered_safe_store32(tc->probe_pa, sentinel)) {\n"
        "\t\t\tpmpfuzz_lowered_record_skip(tc, \"target_store_trapped\");\n"
        "\t\t\treturn;\n"
        "\t\t}\n"
        "\t\tbefore = *(volatile u32 *)tc->probe_pa;\n"
        "\t}\n"
        "\tif (pmpfuzz_lowered_choose_entries(entries, tc->entry_count)) {\n"
        "\t\tpmpfuzz_lowered_record_skip(tc, \"no_unlocked_pmp_entries\");\n"
        "\t\treturn;\n"
        "\t}\n"
        "\tfor (i = 0; i < tc->entry_count; i++) {\n"
        "\t\tif (pmp_get(entries[i], &old_prot[i], &old_addr[i],\n"
        "\t\t\t    &old_log2len[i])) {\n"
        "\t\t\tpmpfuzz_lowered_record_skip(tc, \"pmp_get_failed\");\n"
        "\t\t\treturn;\n"
        "\t\t}\n"
        "\t\t/* A TOR entry uses pmpaddr[entry-1] as the range start address;\n"
        "\t\t * remember that neighbour's raw pmpaddr value so the restore\n"
        "\t\t * path can put it back (otherwise its stale lower bound keeps\n"
        "\t\t * denying the range after the case and U-Boot crashes on it). */\n"
        "\t\tif ((tc->entries[i].prot & PMP_A) == 0x08 && entries[i] > 0)\n"
        "\t\t\told_prev_pmpaddr[i] =\n"
        "\t\t\t\tpmpfuzz_lowered_csr_read_pmpaddr(entries[i] - 1);\n"
        "\t}\n"
        "\tfor (i = 0; i < tc->entry_count; i++) {\n"
        "\t\tif (pmpfuzz_lowered_install_entry(entries[i], tc->entries[i].prot,\n"
        "\t\t\t\t\t\t      tc->entries[i].addr,\n"
        "\t\t\t\t\t\t      tc->entries[i].log2len)) {\n"
        "\t\t\tpmpfuzz_lowered_restore_case(entries, old_prot, old_addr,\n"
        "\t\t\t\t\t\t       old_log2len, old_prev_pmpaddr, tc);\n"
        "\t\t\tpmpfuzz_lowered_record_skip(tc, \"pmp_set_failed\");\n"
        "\t\t\treturn;\n"
        "\t\t}\n"
        "\t}\n"
        "\tpmpfuzz_lowered_fence_rw_rw();\n"
        "\tif (is_sv39) {\n"
        "\t\tif (pmpfuzz_lowered_sv39_begin(tc->va, tc->probe_pa,\n"
        "\t\t\t\t\t       tc->pte_flags, &old_satp)) {\n"
        "\t\t\tpmpfuzz_lowered_restore_case(entries, old_prot, old_addr,\n"
        "\t\t\t\t\t\t       old_log2len, old_prev_pmpaddr, tc);\n"
        "\t\t\tpmpfuzz_lowered_record_skip(tc, \"sv39_setup_failed\");\n"
        "\t\t\treturn;\n"
        "\t\t}\n"
        "\t\tprobe_addr = tc->va;\n"
        "\t}\n"
        "\tif (is_fetch) {\n"
        "\t\tpmpfuzz_lowered_fetch_record(tc->name, tc->profile,\n"
        "\t\t\t\t\t     probe_addr, tc->mpp, tc->satp,\n"
        "\t\t\t\t\t     tc->expected_cause, tc->expected_trap);\n"
        "\t} else if (tc->access == PF_LOWERED_ACCESS_STORE) {\n"
        "\t\tpmpfuzz_lowered_store32_mprv((u32 *)probe_addr,\n"
        "\t\t\t\t\t       (u32)tc->store_value, tc->mpp, &trap);\n"
        "\t} else {\n"
        "\t\tvalue = pmpfuzz_lowered_load32_mprv((const u32 *)probe_addr,\n"
        "\t\t\t\t\t      tc->mpp, &trap);\n"
        "\t}\n"
        "\tif (is_sv39)\n"
        "\t\tpmpfuzz_lowered_sv39_end(old_satp);\n"
        "\tpmpfuzz_lowered_restore_case(entries, old_prot, old_addr,\n"
        "\t\t\t\t       old_log2len, old_prev_pmpaddr, tc);\n"
        "\tif (is_fetch) {\n"
        "\t\t/* result recorded by pmpfuzz_lowered_fetch_record */\n"
        "\t} else if (tc->access == PF_LOWERED_ACCESS_STORE) {\n"
        "\t\t/* Read back the physical probe page: after sv39_end the satp is\n"
        "\t\t * restored to bare, so probing tc->va would read the wrong PA. */\n"
        "\t\tafter = *(volatile u32 *)tc->probe_pa;\n"
        "\t\tpmpfuzz_lowered_record_store(tc, &trap, before, after);\n"
        "\t} else {\n"
        "\t\tpmpfuzz_lowered_record_load(tc, &trap, value);\n"
        "\t}\n"
        "}\n\n"
        "void pmpfuzz_board_generated_manifest(void)\n"
        "{\n"
        "\tunsigned long index;\n\n"
        "\tsbi_printf(PF_TAG\n"
        "\t\t   \"manifest campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s\\n\",\n"
        "\t\t   pmpfuzz_board_manifest_campaign_id(),\n"
        "\t\t   pmpfuzz_board_manifest_round_id(),\n"
        "\t\t   pmpfuzz_board_manifest_case_count(),\n"
        "\t\t   pmpfuzz_board_manifest_sha256());\n"
        f"\tfor (index = 0; index < {selected_count}UL; index++)\n"
        "\t\tpmpfuzz_lowered_run_one(&pmpfuzz_lowered_cases[index], index);\n"
        "}\n"
    )


def render_board_manifest_c(
    *,
    campaign_id: str,
    round_id: str,
    manifest_sha256: str,
    selected_cases: list[str],
    lowered_cases: list[dict[str, Any]] | None = None,
) -> str:
    if lowered_cases:
        if len(lowered_cases) != len(selected_cases):
            raise ValueError("lowered_cases count must match selected_cases count")
        return _render_lowered_board_manifest_c(
            campaign_id=campaign_id,
            round_id=round_id,
            manifest_sha256=manifest_sha256,
            selected_cases=selected_cases,
            lowered_cases=lowered_cases,
        )
    case_lines = "\n".join(f"\t{_c_literal(case)}," for case in selected_cases) or "\tNULL,"
    selected_count = len(selected_cases)
    return (
        "/*\n"
        " * SPDX-License-Identifier: BSD-2-Clause\n"
        " *\n"
        " * Auto-generated by run_u74_board_round.py.\n"
        " */\n\n"
        "#include <sbi/sbi_console.h>\n"
        "#include <sbi/sbi_types.h>\n\n"
        '#define PF_TAG "[pmpfuzz] "\n\n'
        "static const char *const pmpfuzz_selected_cases[] = {\n"
        f"{case_lines}\n"
        "};\n\n"
        "static int pmpfuzz_streq(const char *lhs, const char *rhs)\n"
        "{\n"
        "\tif (!lhs || !rhs)\n"
        "\t\treturn 0;\n"
        "\twhile (*lhs && *rhs && *lhs == *rhs) {\n"
        "\t\tlhs++;\n"
        "\t\trhs++;\n"
        "\t}\n"
        "\treturn *lhs == *rhs;\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_campaign_id(void)\n"
        "{\n"
        f"\treturn {_c_literal(campaign_id)};\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_round_id(void)\n"
        "{\n"
        f"\treturn {_c_literal(round_id)};\n"
        "}\n\n"
        "const char *pmpfuzz_board_manifest_sha256(void)\n"
        "{\n"
        f"\treturn {_c_literal(manifest_sha256)};\n"
        "}\n\n"
        "ulong pmpfuzz_board_manifest_case_count(void)\n"
        "{\n"
        f"\treturn {selected_count}UL;\n"
        "}\n\n"
        "int pmpfuzz_board_case_selected(const char *name)\n"
        "{\n"
        "\tunsigned long index;\n\n"
        "\tif (!name)\n"
        "\t\treturn 0;\n"
        f"\tfor (index = 0; index < {selected_count}UL; index++) {{\n"
        "\t\tif (pmpfuzz_streq(name, pmpfuzz_selected_cases[index]))\n"
        "\t\t\treturn 1;\n"
        "\t}\n"
        "\treturn 0;\n"
        "}\n\n"
        "void pmpfuzz_board_generated_manifest(void)\n"
        "{\n"
        "\tsbi_printf(PF_TAG\n"
        '\t\t   "manifest campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s\\n",\n'
        "\t\t   pmpfuzz_board_manifest_campaign_id(),\n"
        "\t\t   pmpfuzz_board_manifest_round_id(),\n"
        "\t\t   pmpfuzz_board_manifest_case_count(),\n"
        "\t\t   pmpfuzz_board_manifest_sha256());\n"
        "}\n"
    )


def _write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding, newline="\n")


def _copy_exact_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())


def verify_built_payload_embeds_manifest(
    payload_path: Path,
    *,
    campaign_id: str,
    manifest_sha256: str,
) -> None:
    data = payload_path.read_bytes()
    if str(campaign_id).encode("ascii") not in data:
        raise ValueError(f"built payload missing embedded campaign_id: {campaign_id}")
    if str(manifest_sha256).encode("ascii") not in data:
        raise ValueError(f"built payload missing embedded manifest_sha256: {manifest_sha256}")


def _now_utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        input=input_text,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed rc={completed.returncode}: {' '.join(args)}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return completed


def _extract_directive_path(text: str, directive: str) -> str:
    prefix = f"{directive} "
    for raw_line in reversed(str(text or "").splitlines()):
        line = raw_line.strip()
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def _read_kv_text(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = raw_line.partition("=")
        if sep:
            result[key] = value
    return result


def _render_fit_its(
    *,
    fw_payload_incbin: str,
    fdt_incbin: str,
    fdt_lite_incbin: str,
) -> str:
    return (
        "/dts-v1/;\n\n"
        "/ {\n"
        "\t#address-cells = <2>;\n\n"
        "\timages {\n"
        "\t\tfirmware {\n"
        '\t\t\tdescription = "u-boot";\n'
        f'\t\t\tdata = /incbin/("{fw_payload_incbin}");\n'
        '\t\t\ttype = "firmware";\n'
        '\t\t\tarch = "riscv";\n'
        '\t\t\tos = "u-boot";\n'
        "\t\t\tload = <0x0 0x40000000>;\n"
        "\t\t\tentry = <0x0 0x40000000>;\n"
        '\t\t\tcompression = "none";\n'
        "\t\t};\n\n"
        "\t\tfdt {\n"
        f'\t\t\tdata = /incbin/("{fdt_incbin}");\n'
        '\t\t\ttype = "flat_dt";\n'
        '\t\t\tarch = "riscv";\n'
        "\t\t\tload = <0x40400000>;\n"
        '\t\t\tcompression = "none";\n'
        "\t\t};\n\n"
        "\t\tfdt-lite {\n"
        f'\t\t\tdata = /incbin/("{fdt_lite_incbin}");\n'
        '\t\t\ttype = "flat_dt";\n'
        '\t\t\tarch = "riscv";\n'
        "\t\t\tload = <0x40400000>;\n"
        '\t\t\tcompression = "none";\n'
        "\t\t};\n"
        "\t};\n\n"
        "\tconfigurations {\n"
        '\t\tdefault = "config-default";\n\n'
        "\t\tconfig-default {\n"
        '\t\t\tdescription = "StarFive VisionFive V2";\n'
        '\t\t\tfirmware = "firmware";\n'
        '\t\t\tfdt = "fdt";\n'
        "\t\t};\n\n"
        "\t\tconfig-lite {\n"
        '\t\t\tdescription = "StarFive VisionFive V2 Lite";\n'
        '\t\t\tfirmware = "firmware";\n'
        '\t\t\tfdt = "fdt-lite";\n'
        "\t\t};\n"
        "\t};\n"
        "};\n"
    )


def _write_supporting_manifests(
    out_dir: Path,
    *,
    schedule_entries: list[dict],
    observation_profile: dict,
    board_patch_manifest: dict,
    catalog_path: Path,
    seed: int,
    capability_fingerprint: str,
    frozen_universe: dict[str, Any] | None = None,
    frozen_universe_source_path: Path | None = None,
) -> dict[str, str]:
    manifests_dir = out_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    write_json(manifests_dir / "u74-observation-profile.json", observation_profile)
    write_json(manifests_dir / "u74-board-patch-manifest.json", board_patch_manifest)
    universe_path = manifests_dir / "u74-supported-bapc-universe.json"
    if frozen_universe is None:
        universe = build_supported_bapc_universe(
            catalog_path,
            generator_seed=seed,
            capability_fingerprint=capability_fingerprint,
            observation_profile=observation_profile,
        )
        write_json(universe_path, universe)
    else:
        universe = dict(frozen_universe)
        if frozen_universe_source_path is not None and frozen_universe_source_path.exists():
            universe_path.write_bytes(frozen_universe_source_path.read_bytes())
        else:
            write_json(universe_path, universe)
    return {
        "observation_profile": str(manifests_dir / "u74-observation-profile.json"),
        "board_patch_manifest": str(manifests_dir / "u74-board-patch-manifest.json"),
        "supported_bapc_universe": str(universe_path),
        "supported_bapc_universe_sha256": str(universe.get("sha256") or ""),
        "supported_bapc_universe_file_sha256": _sha256_file(universe_path),
        "selected_case_count": str(len(schedule_entries)),
    }


def _git_head_sha(path: Path) -> str:
    return _run_command(["git", "-C", str(path), "rev-parse", "HEAD"]).stdout.strip()


def _git_head_sha_optional(path: Path) -> str:
    try:
        return _git_head_sha(path)
    except Exception:
        return ""


def _safe_label(value: str) -> str:
    text = str(value or "")
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in text)


def _controller_patch_sha256(controller_root: Path) -> str:
    return _sha256_named_files(_controller_patch_paths(controller_root), relative_to=controller_root)


def _git_head_file_text(repo_root: Path, relative_path: Path) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"HEAD:{relative_path.as_posix()}"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _write_controller_patch_artifact(controller_root: Path, out_dir: Path) -> dict[str, str]:
    patch_lines: list[str] = []
    for relative_path in CONTROLLER_PATCH_REL_PATHS:
        current_path = controller_root / relative_path
        if not current_path.exists():
            raise FileNotFoundError(f"Missing controller patch file: {current_path}")
        current_text = current_path.read_text(encoding="utf-8", errors="replace")
        base_text = _git_head_file_text(controller_root, relative_path)
        base_lines = [] if base_text is None else base_text.splitlines(keepends=True)
        current_lines = current_text.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                base_lines,
                current_lines,
                fromfile="/dev/null" if base_text is None else f"a/{relative_path.as_posix()}",
                tofile=f"b/{relative_path.as_posix()}",
                lineterm="\n",
            )
        )
        if not diff_lines:
            continue
        patch_lines.append(
            f"diff --git a/{relative_path.as_posix()} b/{relative_path.as_posix()}\n"
        )
        if base_text is None:
            patch_lines.append("new file mode 100644\n")
        patch_lines.extend(diff_lines)
    patch_path = out_dir / "manifests" / "u74-controller.patch"
    _write_text(patch_path, "".join(patch_lines), encoding="utf-8")
    return {
        "path": str(patch_path),
        "sha256": _sha256_file(patch_path),
    }


def _build_board_patch_manifest(
    *,
    controller_root: Path,
    opensbi_tree: Path,
    generated_manifest_json: Path,
    fw_payload_path: Path,
    fit_path: Path,
    source_tree_for_hash: Path | None = None,
    controller_patch_artifact: dict[str, str] | None = None,
    generated_manifest_c_pre_normalize_sha256: str | None = None,
    frozen_source_manifest_path: Path | None = None,
) -> dict:
    source_root = (source_tree_for_hash or opensbi_tree).resolve()
    board_files = _board_source_paths(source_root)
    runner_path = source_root / "platform" / "generic" / "starfive" / "pmpfuzz_board_runner.c"
    probe_path = source_root / "platform" / "generic" / "starfive" / "security_chain_probe.c"
    generated_manifest_c = source_root / "platform" / "generic" / "starfive" / "pmpfuzz_board_generated_manifest.c"
    generated_manifest_json_sha256 = (
        _sha256_file(generated_manifest_json) if generated_manifest_json.exists() else ""
    )
    manifest = {
        "schema_version": 1,
        "controller_git_sha": _git_head_sha(controller_root),
        "controller_patch_sha256": _controller_patch_sha256(controller_root),
        "opensbi_base_sha": _git_head_sha_optional(opensbi_tree),
        "board_patch_sha256": _sha256_named_files(board_files, relative_to=source_root),
        "runner_sha256": _sha256_file(runner_path),
        "probe_sha256": _sha256_file(probe_path),
        "generated_manifest_c_sha256": _sha256_file(generated_manifest_c),
        "generated_manifest_json_sha256": generated_manifest_json_sha256,
        "fw_payload_sha256": _sha256_file(fw_payload_path),
        "fit_sha256": _sha256_file(fit_path),
    }
    if controller_patch_artifact:
        manifest["controller_patch_diff_path"] = controller_patch_artifact.get("path")
        manifest["controller_patch_diff_sha256"] = controller_patch_artifact.get("sha256")
    if generated_manifest_c_pre_normalize_sha256:
        manifest["generated_manifest_c_pre_normalize_sha256"] = generated_manifest_c_pre_normalize_sha256
    if source_tree_for_hash is not None:
        manifest["frozen_board_source_root"] = str(source_root)
    if frozen_source_manifest_path is not None:
        manifest["frozen_board_source_manifest_path"] = str(frozen_source_manifest_path)
    return manifest


def _freeze_remote_board_sources(
    args: argparse.Namespace,
    *,
    board_build_dir: Path,
    remote_tree: str,
) -> tuple[Path, Path]:
    frozen_root = board_build_dir / "frozen-board-source"
    frozen_root.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, str]] = []
    for relative_path in BOARD_SOURCE_REL_PATHS:
        local_path = frozen_root / relative_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        remote_path = f"{remote_tree}/{relative_path.as_posix()}"
        _run_command(["scp", f"{args.remote_build_host}:{remote_path}", str(local_path)])
        manifest_rows.append(
            {
                "path": relative_path.as_posix(),
                "sha256": _sha256_file(local_path),
            }
        )
    manifest_path = board_build_dir / "frozen-board-source-manifest.json"
    write_json(
        manifest_path,
        {
            "schema_version": 1,
            "source_root": str(frozen_root),
            "files": manifest_rows,
        },
    )
    return frozen_root, manifest_path


def _build_remote_fit(
    args: argparse.Namespace,
    *,
    out_dir: Path,
    manifest_payload: dict,
    schedule_entries: list[dict] | None = None,
) -> dict[str, str]:
    opensbi_tree = args.u74_opensbi_tree.resolve()
    boot_artifacts_dir = args.u74_boot_artifacts_dir.resolve()
    payload_bin = boot_artifacts_dir / "extracted" / "current-u-boot-payload.bin"
    fdt_path = boot_artifacts_dir / "extracted" / "current-fdt.dtb"
    fdt_lite_path = boot_artifacts_dir / "extracted" / "current-fdt-lite.dtb"
    required = [opensbi_tree, payload_bin, fdt_path, fdt_lite_path]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing U74 build inputs: " + ", ".join(missing))

    board_build_dir = out_dir / "board-build"
    board_build_dir.mkdir(parents=True, exist_ok=True)
    fit_its_local = board_build_dir / "u74-fit.its"
    fit_img_local = board_build_dir / "u74-fit.img"
    fw_payload_local = board_build_dir / "fw_payload.bin"
    generated_manifest_json = out_dir / "manifests" / "u74-generated-round-manifest.json"
    generated_manifest_c = opensbi_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_generated_manifest.c"

    lowered_cases = [dict(item) for item in (manifest_payload.get("lowered_cases") or [])]
    if not lowered_cases and schedule_entries:
        # No lowered payload in the (possibly frozen) manifest: materialize it
        # from the schedule entries so the firmware keeps its case loop instead
        # of degrading to a manifest-only image that runs zero cases.
        lowered_cases = _lowered_cases_from_schedule(schedule_entries)
    if lowered_cases:
        validate_direct_board_case_selection(
            [{"name": str(item.get("name") or ""), "lowering": item} for item in lowered_cases]
        )
    elif schedule_entries:
        validate_direct_board_case_selection(schedule_entries)
    else:
        validate_direct_board_case_selection(
            [{"name": case_name} for case_name in (manifest_payload.get("selected_cases") or [])]
        )
    _write_text(
        generated_manifest_c,
        render_board_manifest_c(
            campaign_id=str(manifest_payload.get("campaign_id") or ""),
            round_id=str(manifest_payload.get("round_id") or ""),
            manifest_sha256=str(manifest_payload.get("manifest_sha256") or ""),
            selected_cases=[str(item) for item in (manifest_payload.get("selected_cases") or [])],
            lowered_cases=lowered_cases or None,
        ),
        encoding="utf-8",
    )
    generated_manifest_c_pre_normalize_sha256 = _sha256_file(generated_manifest_c)

    remote_stamp = _now_utc_stamp()
    remote_root = (
        f"{args.remote_build_root.rstrip('/')}/"
        f"{_safe_label(str(manifest_payload.get('campaign_id') or 'u74'))}__"
        f"{_safe_label(str(manifest_payload.get('round_id') or 'round-0000'))}__{remote_stamp}"
    )
    remote_tree = f"{remote_root}/{opensbi_tree.name}"
    remote_fit_its = f"{remote_root}/u74-fit.its"
    remote_fit_img = f"{remote_root}/u74-fit.img"
    remote_payload = f"{remote_root}/current-u-boot-payload.bin"
    remote_fdt = f"{remote_root}/current-fdt.dtb"
    remote_fdt_lite = f"{remote_root}/current-fdt-lite.dtb"

    _write_text(
        fit_its_local,
        _render_fit_its(
            fw_payload_incbin=f"./{opensbi_tree.name}/build/platform/generic/firmware/fw_payload.bin",
            fdt_incbin="./current-fdt.dtb",
            fdt_lite_incbin="./current-fdt-lite.dtb",
        ),
        encoding="utf-8",
    )

    _run_command(["ssh", args.remote_build_host, f"mkdir -p {shlex.quote(remote_root)}"])
    _run_command(["scp", "-r", str(opensbi_tree), f"{args.remote_build_host}:{remote_root}/"])
    _run_command(["scp", str(payload_bin), f"{args.remote_build_host}:{remote_payload}"])
    _run_command(["scp", str(fdt_path), f"{args.remote_build_host}:{remote_fdt}"])
    _run_command(["scp", str(fdt_lite_path), f"{args.remote_build_host}:{remote_fdt_lite}"])
    _run_command(["scp", str(fit_its_local), f"{args.remote_build_host}:{remote_fit_its}"])

    build_cmd = (
        f"find {shlex.quote(remote_tree)} -type f -exec sed -i 's/\\r$//' {{}} + && "
        f"find {shlex.quote(remote_tree)} -type f \\( -name '*.py' -o -name '*.sh' \\) -exec chmod +x {{}} + && "
        f"cd {shlex.quote(remote_tree)} && "
        f"make PLATFORM=generic CROSS_COMPILE=riscv64-linux-gnu- "
        f"FW_PAYLOAD_PATH={shlex.quote(remote_payload)} -j$(nproc) && "
        f"cd {shlex.quote(remote_root)} && "
        f"dtc -I dts -O dtb -o {shlex.quote(Path(remote_fit_img).name)} {shlex.quote(Path(remote_fit_its).name)} && "
        f"sha256sum {shlex.quote(remote_tree)}/build/platform/generic/firmware/fw_payload.bin {shlex.quote(remote_fit_img)}"
    )
    build_output = _run_command(["ssh", args.remote_build_host, build_cmd])
    _write_text(board_build_dir / "remote-build.stdout.txt", build_output.stdout + build_output.stderr, encoding="utf-8")

    _run_command(
        ["scp", f"{args.remote_build_host}:{remote_tree}/build/platform/generic/firmware/fw_payload.bin", str(fw_payload_local)]
    )
    _run_command(["scp", f"{args.remote_build_host}:{remote_fit_img}", str(fit_img_local)])
    frozen_source_root, frozen_source_manifest = _freeze_remote_board_sources(
        args,
        board_build_dir=board_build_dir,
        remote_tree=remote_tree,
    )
    verify_built_payload_embeds_manifest(
        fw_payload_local,
        campaign_id=str(manifest_payload.get("campaign_id") or ""),
        manifest_sha256=str(manifest_payload.get("manifest_sha256") or ""),
    )

    controller_patch_artifact = _write_controller_patch_artifact(
        Path(__file__).resolve().parents[4],
        out_dir,
    )
    board_patch_manifest = _build_board_patch_manifest(
        controller_root=Path(__file__).resolve().parents[4],
        opensbi_tree=opensbi_tree,
        generated_manifest_json=generated_manifest_json,
        fw_payload_path=fw_payload_local,
        fit_path=fit_img_local,
        source_tree_for_hash=frozen_source_root,
        controller_patch_artifact=controller_patch_artifact,
        generated_manifest_c_pre_normalize_sha256=generated_manifest_c_pre_normalize_sha256,
        frozen_source_manifest_path=frozen_source_manifest,
    )
    return {
        "fit_path": str(fit_img_local),
        "fw_payload_path": str(fw_payload_local),
        "fit_sha256": str(board_patch_manifest["fit_sha256"]),
        "board_patch_manifest_path": str(out_dir / "manifests" / "u74-board-patch-manifest.json"),
        "remote_build_root": remote_root,
        "board_patch_manifest_json": json.dumps(board_patch_manifest, ensure_ascii=True, indent=2) + "\n",
    }


def _install_fit_to_board(args: argparse.Namespace, *, fit_path: Path, out_dir: Path, label: str) -> dict[str, str]:
    if not args.board_sudo_password:
        raise ValueError("board sudo password is required for U74 Pilot install")
    tools_dir = args.u74_tools_dir.resolve()
    install_script = tools_dir / "install_sd_p2_probe.sh"
    if not install_script.exists():
        raise FileNotFoundError(f"Missing board install script: {install_script}")
    remote_backup = f"/tmp/{label}-sd-p2-backup.bin"

    _run_command(["scp", "-i", str(args.board_ssh_key), str(fit_path), f"{args.board_ssh_user}@{args.board_ssh_host}:{DEFAULT_U74_REMOTE_BOARD_IMAGE}"])
    _run_command(["scp", "-i", str(args.board_ssh_key), str(install_script), f"{args.board_ssh_user}@{args.board_ssh_host}:{DEFAULT_U74_REMOTE_BOARD_INSTALL}"])
    remote_cmd = (
        f"read -r SUDO_PW; export SUDO_PW; chmod +x {shlex.quote(DEFAULT_U74_REMOTE_BOARD_INSTALL)} && "
        f"{shlex.quote(DEFAULT_U74_REMOTE_BOARD_INSTALL)} {shlex.quote(DEFAULT_U74_REMOTE_BOARD_IMAGE)} /dev/mmcblk1p2 {shlex.quote(remote_backup)}"
    )
    install = _run_command(
        [
            "ssh",
            "-i",
            str(args.board_ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{args.board_ssh_user}@{args.board_ssh_host}",
            remote_cmd,
        ],
        input_text=args.board_sudo_password + "\n",
    )
    _write_text(out_dir / "board-build" / "board-install.stdout.txt", install.stdout + install.stderr, encoding="utf-8")
    return {
        "remote_image": DEFAULT_U74_REMOTE_BOARD_IMAGE,
        "remote_backup": remote_backup,
    }


def _collect_board_boot_chain_evidence(
    args: argparse.Namespace,
    *,
    out_dir: Path,
    label: str,
    p2_prefix_bytes: int,
) -> dict[str, Any]:
    if not args.board_sudo_password:
        raise ValueError("board sudo password is required for U74 boot-chain verification")
    remote_cmd = (
        "set -e; "
        "read -r SUDO_PW; export SUDO_PW; "
        "sudo_cmd() { printf '%s\\n' \"$SUDO_PW\" | sudo -S -p '' \"$@\"; }; "
        "echo '=== identity ==='; "
        "printf 'hostname='; hostname; "
        "printf 'date='; date -Iseconds; "
        "uname -a; "
        "printf 'kernel_cmdline='; cat /proc/cmdline; "
        "echo '=== mmc sysfs ==='; "
        "for key in cid csd name oemid manfid date serial hwrev fwrev; do "
        "  printf '%s=' \"$key\"; cat \"/sys/block/mmcblk1/device/$key\"; "
        "done; "
        "echo '=== blockdev ==='; "
        "for dev in /dev/mmcblk1 /dev/mmcblk1p1 /dev/mmcblk1p2; do "
        "  if [ -b \"$dev\" ]; then "
        "    echo \"${dev}_exists=1\"; "
        "    printf '%s_size_bytes=' \"$dev\"; sudo_cmd blockdev --getsize64 \"$dev\"; "
        "  else "
        "    echo \"${dev}_exists=0\"; "
        "  fi; "
        "done; "
        "echo '=== blkid ==='; "
        "sudo_cmd blkid /dev/mmcblk1 /dev/mmcblk1p1 /dev/mmcblk1p2 || true; "
        "echo '=== sfdisk ==='; "
        "sudo_cmd sfdisk -d /dev/mmcblk1; "
        "echo '=== sha256 ==='; "
        "printf 'mmcblk1p1_full_sha256='; "
        "sudo_cmd dd if=/dev/mmcblk1p1 bs=1M count=2 status=none | sha256sum | cut -d ' ' -f1; "
        f"printf 'mmcblk1p2_prefix_{int(p2_prefix_bytes)}_sha256='; "
        f"sudo_cmd dd if=/dev/mmcblk1p2 bs={int(p2_prefix_bytes)} count=1 status=none | sha256sum | cut -d ' ' -f1; "
        "printf 'mmcblk1p2_full_sha256='; "
        "sudo_cmd dd if=/dev/mmcblk1p2 bs=1M count=4 status=none | sha256sum | cut -d ' ' -f1; "
        "echo '=== gpt first sectors sha ==='; "
        "printf 'mmcblk1_first_34_sectors_sha256='; "
        "sudo_cmd dd if=/dev/mmcblk1 bs=512 count=34 status=none | sha256sum | cut -d ' ' -f1"
    )
    output = _run_command(
        [
            "ssh",
            "-i",
            str(args.board_ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{args.board_ssh_user}@{args.board_ssh_host}",
            remote_cmd,
        ],
        input_text=args.board_sudo_password + "\n",
    )
    raw_path = out_dir / "manifests" / f"{label}-boot-chain-evidence-after-install.txt"
    parsed_path = out_dir / "manifests" / f"{label}-boot-chain-evidence-after-install.json"
    text = output.stdout + output.stderr
    _write_text(raw_path, text, encoding="utf-8")
    evidence = parse_boot_chain_evidence_text(text)
    write_json(parsed_path, evidence)
    return {
        "raw_path": str(raw_path),
        "parsed_path": str(parsed_path),
        "evidence": evidence,
    }


def _verify_board_boot_chain_after_install(
    args: argparse.Namespace,
    *,
    boot_chain_policy: dict[str, Any],
    fit_path: Path,
    out_dir: Path,
    label: str,
) -> dict[str, Any]:
    if not boot_chain_policy:
        return {"enabled": False}
    fit_sha256 = _sha256_file(fit_path)
    fit_bytes = fit_path.stat().st_size
    policy_errors = validate_boot_chain_policy(
        boot_chain_policy,
        actual_fit_sha256=fit_sha256,
        actual_fit_bytes=fit_bytes,
    )
    if policy_errors:
        raise RuntimeError("U74 boot-chain policy does not match FIT: " + "; ".join(policy_errors))
    collected = _collect_board_boot_chain_evidence(
        args,
        out_dir=out_dir,
        label=label,
        p2_prefix_bytes=fit_bytes,
    )
    runtime_errors = validate_runtime_boot_chain_evidence(
        boot_chain_policy,
        dict(collected["evidence"]),
    )
    report = {
        "schema_version": 1,
        "enabled": True,
        "policy_path": str(args.u74_boot_chain_policy),
        "fit_sha256": fit_sha256,
        "fit_bytes": fit_bytes,
        "evidence_raw_path": collected["raw_path"],
        "evidence_parsed_path": collected["parsed_path"],
        "errors": runtime_errors,
        "error_count": len(runtime_errors),
        "valid": len(runtime_errors) == 0,
    }
    report_path = out_dir / "manifests" / f"{label}-boot-chain-validation.json"
    write_json(report_path, report)
    report["report_path"] = str(report_path)
    if runtime_errors:
        raise RuntimeError("U74 boot-chain verification failed: " + "; ".join(runtime_errors))
    return report


def _run_boot_mode_precheck(args: argparse.Namespace, *, out_dir: Path, label: str) -> dict[str, str]:
    script = args.u74_tools_dir.resolve() / "read_board_boot_mode.ps1"
    output = _run_command(
        [
            "pwsh.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-OutputDir",
            str(out_dir),
            "-Label",
            label,
            "-SshUser",
            args.board_ssh_user,
            "-SshHost",
            args.board_ssh_host,
            "-SshKey",
            str(args.board_ssh_key),
            "-SudoPassword",
            args.board_sudo_password,
        ]
    )
    manifest_path = Path(_extract_directive_path(output.stdout, "__MANIFEST__"))
    if not manifest_path.exists():
        raise RuntimeError("boot-mode manifest was not produced")
    result = _read_kv_text(manifest_path)
    result["manifest_path"] = str(manifest_path)
    stdout_path = _extract_directive_path(output.stdout, "__STDOUT__")
    if stdout_path:
        result["stdout_path"] = stdout_path
    return result


def _run_uart_capture(args: argparse.Namespace, *, out_dir: Path, label: str) -> dict[str, str]:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    uart_path = raw_dir / "uart.txt"
    script = args.u74_tools_dir.resolve() / "capture_security_chain_boot.ps1"
    capture_args = [
        "pwsh.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(script),
        "-Port",
        args.board_uart_port,
        "-Baud",
        str(args.board_uart_baud),
        "-Seconds",
        str(args.capture_seconds),
        "-Output",
        str(uart_path),
        "-WaitForBoot",
        "-WaitTimeoutSeconds",
        str(args.capture_wait_timeout_seconds),
    ]
    if getattr(args, "board_reboot_over_ssh", False):
        # The capture script's own -RebootOverSsh uses Start-Process for ssh,
        # which is unreliable from -NonInteractive pwsh. Instead: open the
        # capture in the background, then trigger the reboot with a direct ssh
        # invocation, then wait for the capture to finish.
        capture = subprocess.Popen(
            capture_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        time.sleep(3)  # let the serial port open before the reboot drops the link
        reboot_cmd = (
            f"printf '%s\\n' '{args.board_sudo_password}' | sudo -S -p '' reboot"
        )
        subprocess.run(
            [
                "ssh",
                "-i",
                str(args.board_ssh_key),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=8",
                f"{args.board_ssh_user}@{args.board_ssh_host}",
                reboot_cmd,
            ],
            check=False,
            timeout=60,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output_text, _ = capture.communicate(timeout=int(args.capture_wait_timeout_seconds) + 120)
        output = subprocess.CompletedProcess(args=capture_args, returncode=capture.returncode,
                                             stdout=output_text, stderr="")
    else:
        output = _run_command(capture_args)
    summary_path = Path(_extract_directive_path(output.stdout, "__SUMMARY_WRITTEN__"))
    if not uart_path.exists() or not summary_path.exists():
        raise RuntimeError("UART capture did not produce raw log and summary")
    result = _read_kv_text(summary_path)
    result["summary_path"] = str(summary_path)
    result["uart_path"] = str(uart_path)
    if result.get("structured_events"):
        result["structured_events_path"] = str(result.get("structured_events"))
    return result


def _summarize_board_run_manifest(
    *,
    board_patch_manifest: dict,
    manifest_payload: dict,
    precheck: dict[str, str],
    uart_summary: dict[str, str],
    raw_uart_text: str,
) -> dict:
    early_boot_source = "unknown"
    if "Trying to boot from MMC2" in raw_uart_text:
        early_boot_source = "MMC2"
    elif "Trying to boot from MMC" in raw_uart_text or "Trying to boot from SD" in raw_uart_text:
        early_boot_source = "SD"
    elif "Trying to boot from SPI" in raw_uart_text:
        early_boot_source = "SPI"
    return {
        "schema_version": 1,
        "controller_git_sha": board_patch_manifest.get("controller_git_sha"),
        "controller_patch_sha256": board_patch_manifest.get("controller_patch_sha256"),
        "opensbi_base_sha": board_patch_manifest.get("opensbi_base_sha"),
        "board_patch_sha256": board_patch_manifest.get("board_patch_sha256"),
        "runner_sha256": board_patch_manifest.get("runner_sha256"),
        "probe_sha256": board_patch_manifest.get("probe_sha256"),
        "fit_sha256": board_patch_manifest.get("fit_sha256"),
        "pre_capture_rgpio0": precheck.get("rgpio0"),
        "pre_capture_rgpio1": precheck.get("rgpio1"),
        "boot_select": precheck.get("boot_select"),
        "boot_mode": precheck.get("boot_mode"),
        "cold_power_cycle_confirmed": (
            str(uart_summary.get("boot_seen") or "").lower() == "true"
            and str(uart_summary.get("boot_from_sd") or "").lower() == "true"
            and str(uart_summary.get("boot_from_spi") or "").lower() == "false"
        ),
        "cold_power_cycle_confirmation_basis": "manual_user_action_required_plus_early_uart_boot_seen",
        "early_boot_source": early_boot_source,
        "boot_from_sd": uart_summary.get("boot_from_sd"),
        "boot_from_spi": uart_summary.get("boot_from_spi"),
        "campaign_id": manifest_payload.get("campaign_id"),
        "round_id": manifest_payload.get("round_id"),
        "generated_manifest_sha256": manifest_payload.get("manifest_sha256"),
        "capability_fingerprint": manifest_payload.get("capability_fingerprint"),
        "supported_bapc_universe_sha256": manifest_payload.get("supported_bapc_universe_sha256"),
        "supported_bapc_universe_file_sha256": manifest_payload.get("supported_bapc_universe_file_sha256"),
        "validator_profile": manifest_payload.get("validator_profile"),
        "observation_profile_id": manifest_payload.get("observation_profile_id"),
    }


def _run_real_round(
    args: argparse.Namespace,
    *,
    out_dir: Path,
    schedule_entries: list[dict],
    catalog_by_case: dict[str, dict],
    dut_capability: dict,
    manifest_payload: dict,
    validation_context: dict[str, Any],
    loaded_board_patch_manifest: dict[str, Any] | None = None,
) -> dict:
    try:
        runner_started_at = float(validation_context.get("_runner_started_at"))
    except (TypeError, ValueError):
        runner_started_at = time.perf_counter()
    build_started_at = time.perf_counter()
    validate_direct_board_case_selection(schedule_entries)
    manifests_dir = out_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    boot_chain_policy = _load_boot_chain_policy(getattr(args, "u74_boot_chain_policy", None))
    prebuilt_fit_path = getattr(args, "prebuilt_fit_path", None)
    if prebuilt_fit_path is not None:
        fit_path = Path(prebuilt_fit_path).resolve()
        if not fit_path.exists():
            raise FileNotFoundError(f"Missing prebuilt U74 FIT: {fit_path}")
        board_patch_manifest = dict(
            loaded_board_patch_manifest
            or _load_board_patch_manifest(getattr(args, "u74_board_patch_manifest", None))
        )
        if not board_patch_manifest:
            raise ValueError("prebuilt U74 FIT requires a loaded board patch manifest")
        actual_fit_sha256 = _sha256_file(fit_path)
        expected_fit_sha256 = str(board_patch_manifest.get("fit_sha256") or "")
        if expected_fit_sha256 and expected_fit_sha256 != actual_fit_sha256:
            raise ValueError(
                "prebuilt U74 FIT sha256 mismatch: "
                f"expected {expected_fit_sha256}, got {actual_fit_sha256}"
            )
        board_patch_manifest["fit_sha256"] = actual_fit_sha256
        build_meta = {
            "fit_path": str(fit_path),
            "fit_sha256": actual_fit_sha256,
            "board_patch_manifest_path": str(manifests_dir / "u74-board-patch-manifest.json"),
            "remote_build_root": "",
            "build_source": "prebuilt-fit",
        }
    else:
        build_meta = _build_remote_fit(
            args,
            out_dir=out_dir,
            manifest_payload=manifest_payload,
            schedule_entries=schedule_entries,
        )
        board_patch_manifest = json.loads(build_meta["board_patch_manifest_json"])
    build_elapsed_seconds = _elapsed_seconds(build_started_at)
    write_json(Path(build_meta["board_patch_manifest_path"]), board_patch_manifest)

    label = _safe_label(f"{manifest_payload['campaign_id']}_{manifest_payload['round_id']}_{_now_utc_stamp()}")
    install_started_at = time.perf_counter()
    install_meta = _install_fit_to_board(args, fit_path=Path(build_meta["fit_path"]), out_dir=out_dir, label=label)
    boot_chain_meta = _verify_board_boot_chain_after_install(
        args,
        boot_chain_policy=boot_chain_policy,
        fit_path=Path(build_meta["fit_path"]),
        out_dir=out_dir,
        label=label,
    )
    install_elapsed_seconds = _elapsed_seconds(install_started_at)
    serial_started_at = time.perf_counter()
    precheck = _run_boot_mode_precheck(args, out_dir=out_dir, label=f"{label}_bootmode")
    uart_summary = _run_uart_capture(args, out_dir=out_dir, label=label)
    serial_elapsed_seconds = _elapsed_seconds(serial_started_at)
    parse_started_at = time.perf_counter()
    raw_uart_text = Path(uart_summary["uart_path"]).read_text(encoding="utf-8", errors="replace")
    structured_events_path = Path(str(uart_summary.get("structured_events_path") or ""))
    if not structured_events_path.exists():
        raise RuntimeError("UART capture did not produce structured_events timing sidecar")
    structured_uart_events = [
        json.loads(line)
        for line in structured_events_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    parse_elapsed_seconds = _elapsed_seconds(parse_started_at)

    board_run_manifest = _summarize_board_run_manifest(
        board_patch_manifest=board_patch_manifest,
        manifest_payload=manifest_payload,
        precheck=precheck,
        uart_summary=uart_summary,
        raw_uart_text=raw_uart_text,
    )
    board_run_manifest["fit_remote_image"] = install_meta["remote_image"]
    board_run_manifest["fit_remote_backup"] = install_meta["remote_backup"]
    board_run_manifest["boot_chain_verification"] = boot_chain_meta
    board_run_manifest["remote_build_root"] = build_meta["remote_build_root"]
    board_run_manifest["fit_build_source"] = str(build_meta.get("build_source") or "rebuilt-fit")
    board_run_manifest["structured_events_path"] = str(structured_events_path)
    board_run_manifest["timing_source"] = "uart_structured_events"
    board_run_manifest["generation_elapsed_seconds"] = _elapsed_value(
        validation_context.get("generation_elapsed_seconds"),
        fallback=_elapsed_seconds(runner_started_at, build_started_at),
    )
    board_run_manifest["build_elapsed_seconds"] = build_elapsed_seconds
    board_run_manifest["install_elapsed_seconds"] = install_elapsed_seconds
    board_run_manifest["serial_elapsed_seconds"] = serial_elapsed_seconds
    board_run_manifest["runner_elapsed_seconds"] = _elapsed_seconds(runner_started_at)
    board_run_manifest["parse_elapsed_seconds"] = parse_elapsed_seconds
    board_run_manifest["validation_elapsed_seconds"] = MIN_ELAPSED_SECONDS
    board_run_manifest_path = out_dir / "manifests" / "u74-board-run-manifest.json"
    write_json(board_run_manifest_path, board_run_manifest)

    validation_started_at = time.perf_counter()
    report = write_round_materialization(
        out_dir,
        dut="u74",
        round_campaign_id=str(
            getattr(args, "campaign_id", "")
            or f"{manifest_payload['campaign_id']}__{manifest_payload['round_id']}"
        ),
        schedule_entries=schedule_entries,
        catalog_by_case=catalog_by_case,
        raw_uart_text=raw_uart_text,
        board_patch_manifest=board_patch_manifest,
        dut_capability={
            **dut_capability,
            "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        },
        structured_uart_events=structured_uart_events,
        generated_round_manifest=manifest_payload,
        board_run_manifest=board_run_manifest,
        validation_context=validation_context,
    )
    board_run_manifest["validation_elapsed_seconds"] = _elapsed_seconds(validation_started_at)
    board_run_manifest["runner_elapsed_seconds"] = _elapsed_seconds(runner_started_at)
    write_json(board_run_manifest_path, board_run_manifest)
    report = validate_round_artifacts(
        out_dir,
        schedule_entries=schedule_entries,
        validation_context=validation_context,
    )

    extra_errors: list[str] = []
    if precheck.get("boot_mode_read_result") != "pass":
        extra_errors.append("boot_mode_read_not_pass")
    if precheck.get("rgpio0") != "1":
        extra_errors.append("pre_capture_rgpio0_not_1")
    if precheck.get("rgpio1") != "0":
        extra_errors.append("pre_capture_rgpio1_not_0")
    if precheck.get("boot_select") != "1":
        extra_errors.append("pre_capture_boot_select_not_1")
    if precheck.get("boot_mode") != "sdio3":
        extra_errors.append("pre_capture_boot_mode_not_sdio3")
    if "Trying to boot from MMC2" not in raw_uart_text:
        extra_errors.append("early_uart_missing_mmc2")
    if str(uart_summary.get("boot_from_sd") or "").lower() != "true":
        extra_errors.append("boot_from_sd_not_true")
    if str(uart_summary.get("boot_from_spi") or "").lower() != "false":
        extra_errors.append("boot_from_spi_not_false")

    report["generated_manifest_path"] = str(out_dir / "manifests" / "u74-generated-round-manifest.json")
    report["board_run_manifest_path"] = str(board_run_manifest_path)
    report["fit_sha256"] = board_patch_manifest.get("fit_sha256")
    report["pre_capture_boot_mode"] = precheck.get("boot_mode")
    report["pre_capture_boot_select"] = precheck.get("boot_select")
    report["pre_capture_rgpio0"] = precheck.get("rgpio0")
    report["pre_capture_rgpio1"] = precheck.get("rgpio1")
    report["boot_from_sd"] = uart_summary.get("boot_from_sd")
    report["boot_from_spi"] = uart_summary.get("boot_from_spi")
    report["errors"] = list(report.get("errors") or []) + extra_errors
    report["error_count"] = len(report["errors"])
    report["case_result_manifest_reconciled"] = report["error_count"] == 0
    write_json(out_dir / "validator" / "report.json", report)
    return report


def main(argv: list[str] | None = None) -> int:
    runner_started_at = time.perf_counter()
    generation_started_at = runner_started_at
    args = build_parser().parse_args(argv)
    if args.dut != "u74":
        raise ValueError(f"run_u74_board_round only supports dut=u74, got {args.dut!r}")
    if args.mode == "real":
        missing = [
            name
            for name, value in (
                ("--board-ssh-host", args.board_ssh_host),
                ("--board-ssh-user", args.board_ssh_user),
                ("--board-ssh-key", args.board_ssh_key),
                ("--board-uart-port", args.board_uart_port),
            )
            if not value
        ]
        if args.prebuilt_fit_path is None and not args.remote_build_host:
            missing.append("--remote-build-host")
        if missing:
            raise ValueError(
                "real U74 mode requires explicit hardware configuration: "
                + ", ".join(missing)
            )

    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    schedule_entries = _load_schedule(args.schedule)
    validate_direct_board_case_selection(schedule_entries)
    observation_profile = _load_observation_profile(args.u74_observation_profile)
    board_patch_manifest = _load_board_patch_manifest(args.u74_board_patch_manifest)
    frozen_generated_manifest = _load_generated_round_manifest(args.u74_generated_round_manifest)
    campaign_id, round_id = split_round_campaign_id(args.campaign_id)
    validation_context, frozen_universe, frozen_universe_source_path = _resolve_round_validation_context(
        args=args,
        campaign_id=campaign_id,
        round_id=round_id,
        observation_profile=observation_profile,
    )
    catalog = load_json(args.u74_catalog)
    catalog_by_case = {
        str(item.get("case") or ""): dict(item)
        for item in (catalog.get("cases") or [])
        if isinstance(item, dict) and item.get("case")
    }
    dut_capability = capability_for_dut("u74", available=True)
    supporting_paths = _write_supporting_manifests(
        out_dir,
        schedule_entries=schedule_entries,
        observation_profile=observation_profile,
        board_patch_manifest=board_patch_manifest,
        catalog_path=args.u74_catalog,
        seed=args.seed,
        capability_fingerprint=str(validation_context.get("capability_fingerprint") or ""),
        frozen_universe=frozen_universe,
        frozen_universe_source_path=frozen_universe_source_path,
    )
    generated_manifest_path = out_dir / "manifests" / "u74-generated-round-manifest.json"
    if frozen_generated_manifest:
        manifest_payload = dict(frozen_generated_manifest)
        if str(manifest_payload.get("campaign_id") or "") != campaign_id:
            raise ValueError("frozen generated manifest campaign_id mismatch")
        if str(manifest_payload.get("round_id") or "") != round_id:
            raise ValueError("frozen generated manifest round_id mismatch")
        if int(manifest_payload.get("case_count") or 0) != len(schedule_entries):
            raise ValueError("frozen generated manifest case_count mismatch")
        selected_cases = [str(item.get("name") or "") for item in schedule_entries]
        if [str(item) for item in (manifest_payload.get("selected_cases") or [])] != selected_cases:
            raise ValueError("frozen generated manifest selected_cases mismatch")
        expected_manifest_sha256 = str(manifest_payload.get("manifest_sha256") or "")
        if not expected_manifest_sha256:
            raise ValueError("frozen generated manifest missing manifest_sha256")
        recomputed_manifest_sha256 = _manifest_sha256(
            {key: value for key, value in manifest_payload.items() if key != "manifest_sha256"}
        )
        if expected_manifest_sha256 != recomputed_manifest_sha256:
            raise ValueError("frozen generated manifest recomputed sha256 mismatch")
        expected_capability_fingerprint = str(validation_context.get("capability_fingerprint") or "")
        if expected_capability_fingerprint and str(manifest_payload.get("capability_fingerprint") or "") != expected_capability_fingerprint:
            raise ValueError("frozen generated manifest capability_fingerprint mismatch")
        expected_universe_sha256 = str(validation_context.get("supported_bapc_universe_sha256") or "")
        if expected_universe_sha256 and str(manifest_payload.get("supported_bapc_universe_sha256") or "") != expected_universe_sha256:
            raise ValueError("frozen generated manifest supported_bapc_universe_sha256 mismatch")
        expected_universe_file_sha256 = str(validation_context.get("supported_bapc_universe_file_sha256") or "")
        if expected_universe_file_sha256 and str(manifest_payload.get("supported_bapc_universe_file_sha256") or "") != expected_universe_file_sha256:
            raise ValueError("frozen generated manifest supported_bapc_universe_file_sha256 mismatch")
        expected_profile = str(validation_context.get("validator_profile") or ENGINEERING_SMOKE_VALIDATOR_PROFILE)
        if expected_profile and str(manifest_payload.get("validator_profile") or "") != expected_profile:
            raise ValueError("frozen generated manifest validator_profile mismatch")
        expected_observation_profile_id = str(observation_profile.get("observation_profile_id") or "")
        if expected_observation_profile_id and str(manifest_payload.get("observation_profile_id") or "") != expected_observation_profile_id:
            raise ValueError("frozen generated manifest observation_profile_id mismatch")
        _copy_exact_file(args.u74_generated_round_manifest.resolve(), generated_manifest_path)
        manifest_sha256 = expected_manifest_sha256
    else:
        lowered_cases = _lowered_cases_from_schedule(schedule_entries)
        manifest_payload = {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "round_id": round_id,
            "case_count": len(schedule_entries),
            "selected_cases": [str(item.get("name") or "") for item in schedule_entries],
            "lowered_cases": lowered_cases,
            "observation_profile_id": str(observation_profile.get("observation_profile_id") or ""),
            "board_patch_manifest": supporting_paths["board_patch_manifest"],
            "supported_bapc_universe": supporting_paths["supported_bapc_universe"],
            "supported_bapc_universe_sha256": supporting_paths["supported_bapc_universe_sha256"],
            "supported_bapc_universe_file_sha256": supporting_paths["supported_bapc_universe_file_sha256"],
            "capability_fingerprint": str(validation_context.get("capability_fingerprint") or ""),
            "validator_profile": str(validation_context.get("validator_profile") or ENGINEERING_SMOKE_VALIDATOR_PROFILE),
        }
        manifest_sha256 = _manifest_sha256(manifest_payload)
        manifest_payload["manifest_sha256"] = manifest_sha256
        write_json(generated_manifest_path, manifest_payload)
    validation_context["_runner_started_at"] = runner_started_at
    validation_context["generation_elapsed_seconds"] = _elapsed_seconds(generation_started_at)

    if args.mode == "fake":
        uart_text = synthesize_fake_uart_log(
            schedule_entries=schedule_entries,
            catalog_by_case=catalog_by_case,
            campaign_id=campaign_id,
            round_id=round_id,
            manifest_sha256=manifest_sha256,
        )
        structured_events = synthesize_fake_structured_uart_events(uart_text)
        report = write_round_materialization(
            out_dir,
            dut="u74",
            round_campaign_id=args.campaign_id,
            schedule_entries=schedule_entries,
            catalog_by_case=catalog_by_case,
            raw_uart_text=uart_text,
            board_patch_manifest=board_patch_manifest,
            dut_capability={
                **dut_capability,
                "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
            },
            structured_uart_events=structured_events,
            generated_round_manifest=manifest_payload,
            validation_context=validation_context,
        )
        report["generated_manifest_path"] = str(generated_manifest_path)
        report["parsed_case_count"] = len(parse_uart_log(uart_text).get("cases") or [])
        write_json(out_dir / "validator" / "report.json", report)
        return 0 if int(report.get("error_count") or 0) == 0 else 1

    try:
        report = _run_real_round(
            args,
            out_dir=out_dir,
            schedule_entries=schedule_entries,
            catalog_by_case=catalog_by_case,
            dut_capability=dut_capability,
            manifest_payload=manifest_payload,
            validation_context=validation_context,
            loaded_board_patch_manifest=board_patch_manifest,
        )
    except Exception as exc:
        failure_report = {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "round_id": round_id,
            "scheduled_case_count": len(schedule_entries),
            "executed_case_count": 0,
            "observation_qualified_case_count": 0,
            "runner_begin_count": 0,
            "runner_end_count": 0,
            "manifest_case_count": len(schedule_entries),
            "applicable_count": 0,
            "unsupported_count": 0,
            "inconclusive_count": 0,
            "infrastructure_failure_count": len(schedule_entries),
            "unique_target_specific_bins": 0,
            "new_bins_in_round": 0,
            "error_count": 1,
            "errors": [str(exc)],
            "case_result_manifest_reconciled": False,
            "generated_manifest_path": str(out_dir / "manifests" / "u74-generated-round-manifest.json"),
        }
        write_json(out_dir / "validator" / "report.json", failure_report)
        return 1

    return 0 if int(report.get("error_count") or 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
