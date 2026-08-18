from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .capabilities import oracle_applicability_for_case
from .c910_nonpmp import (
    BOOTSTRAP_SEED,
    C910_NONPMP_CAPABILITY_PROFILE,
    C910_NONPMP_DUT,
    C910_NONPMP_TARGET,
    _result_from_case,
    bootstrap_capability,
    bootstrap_cases,
    parse_uart_records,
)
from .coverage import compute_coverage_targets, write_coverage
from .coverage_universe import write_coverage_universes
from .schema import write_aggregate, write_json
from .timeline import TimelineRecorder
from .triage import triage_run, write_report


DYNAMIC_MANIFEST_SCHEMA_VERSION = 2
GENERATED_MANIFEST_SCHEMA_VERSION = 3
DEFAULT_TIMEBASE_HZ = 3_000_000
CATALOG_SLOT_COUNT = 4

# runner_code: 0 = phase-handled catalog case (probe phase function emits it);
# 1..2 = parameterized case-runner executes from manifest params.
GENERATED_RUNNER_CODES = {
    "sv39_access": 1,
    "mprv_bare": 2,
    "sum_fetch": 3,
    "real_mode": 4,
    "fetch_basic": 5,
}
GENERATED_RUNNER_TO_PARSER = {
    "sv39_access": "mprv",
    "mprv_bare": "mprv",
    "sum_fetch": "sum-fetch",
    "real_mode": "real-mode",
    "fetch_basic": "fetch-test",
}
# Access/privilege numeric encodings shared with the probe's case-runner.
_ACCESS_CODE = {"load": 0, "store": 1, "fetch": 2}
_PRIV_CODE = {"m": 0, "s": 1, "u": 2}
_TRANS_CODE = {"bare": 0, "sv39": 1}
_RWX_CODE = {"r": 0x1, "w": 0x2, "x": 0x4}
_GENERATED_PROFILE = "c910-nonpmp-gen"
DEFAULT_PILOT_CASE_NAMES = (
    "c910-nonpmp-privilege__bare-s-ecall-fw-text",
    "c910-nonpmp-side-effect__real-u-store-fw-data",
    "c910-nonpmp-sv39__sv39-u-load-user-page",
    "c910-nonpmp-tlb__tlb-clear-nosfence",
    "c910-nonpmp-fetch__sv39-u-exec-nx-page",
    "c910-nonpmp-fetch__s-fetch-u-page-sum0",
    "c910-nonpmp-side-effect__translated-u-store-final-pa",
    "c910-nonpmp-side-effect__store-stale-after-w-clear-nosfence",
)

_CASE_BEGIN_RE = re.compile(
    r"\[nonpmp-chain\] case begin case_id=(?P<case_id>\S+) "
    r"scenario_hash=(?P<scenario_hash>[0-9a-fA-F]+) "
    r"record=(?P<record>\S+) start_ticks=(?P<start_ticks>\d+)"
)
_CASE_END_RE = re.compile(
    r"\[nonpmp-chain\] case end case_id=(?P<case_id>\S+) "
    r"scenario_hash=(?P<scenario_hash>[0-9a-fA-F]+) "
    r"record=(?P<record>\S+) end_ticks=(?P<end_ticks>\d+) "
    r"elapsed_ticks=(?P<elapsed_ticks>\d+)"
)


def catalog_cases(*, capability: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    expanded = _expanded_catalog_cases()
    if capability is None:
        return expanded
    return [case for case in expanded if oracle_applicability_for_case(case, capability) == "valid"]


@lru_cache(maxsize=1)
def _expanded_catalog_cases() -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for base_case in bootstrap_cases(capability=None):
        for slot in range(CATALOG_SLOT_COUNT):
            expanded.append(_slot_case(base_case=base_case, slot=slot, index=len(expanded)))
    return expanded


def _slot_case(*, base_case: dict[str, Any], slot: int, index: int) -> dict[str, Any]:
    case = json.loads(json.dumps(base_case, sort_keys=True, ensure_ascii=True))
    base_name = str(base_case["name"])
    base_record = str(base_case["uart_record"])
    runner_kind = _runner_kind_for_case(base_case)
    slot_fields = _slot_fields_for_case(base_case=base_case, runner_kind=runner_kind,
                                        slot=slot)
    if slot == 0:
        case_name = base_name
    else:
        case_name = f"{base_name}-slot{slot}"
    case["name"] = case_name
    case["index"] = int(index)
    case["uart_record"] = base_record
    case.update(slot_fields)
    case["runner_params"] = {
        "runner_kind": runner_kind,
        "phase": base_record,
        "slot": int(slot),
        "slot_sensitive": bool(slot_fields.get("slot_sensitive")),
        "page_bank": slot_fields.get("page_bank"),
        "va_bank": slot_fields.get("va_bank"),
        "asid_bank": slot_fields.get("asid_bank"),
    }
    case["scenario_spec"] = {
        "schema_version": 2,
        "target": C910_NONPMP_TARGET,
        "profile": str(case["profile"]),
        "phase": base_record,
        "slot": int(slot),
        "runner_kind": runner_kind,
        "page_bank": slot_fields.get("page_bank"),
        "va_bank": slot_fields.get("va_bank"),
        "asid_bank": slot_fields.get("asid_bank"),
    }
    case["scenario_hash"] = _case_hash(case["scenario_spec"])
    return case


def _runner_kind_for_case(case: dict[str, Any]) -> str:
    parser = str(case.get("uart_parser") or "")
    translation = str(case.get("translation") or "")
    security_focus = str(case.get("security_focus") or "")
    profile = str(case.get("profile") or "")
    if parser == "real-mode":
        return "real_mode"
    if translation == "bare" and security_focus in {"mprv_bare", "misaligned"}:
        return "mprv_bare"
    if parser == "sum-fetch":
        return "sum_fetch"
    if security_focus == "fetch_itlb_stale":
        return "fetch_stale"
    if security_focus in {"fetch_execute", "fence_i", "illegal_fetch"}:
        return "fetch_basic"
    if security_focus == "translated_pa_side_effect":
        return "translated_side_effect"
    if security_focus == "store_stale":
        return "store_stale"
    if profile == "c910-nonpmp-tlb":
        return "tlb_access"
    if profile == "c910-nonpmp-sv39":
        return "sv39_access"
    return "fixed_phase"


def _slot_fields_for_case(*, base_case: dict[str, Any], runner_kind: str,
                          slot: int) -> dict[str, Any]:
    access = str(base_case.get("access") or "")
    translation = str(base_case.get("translation") or "")
    fields: dict[str, Any] = {
        "slot_sensitive": False,
        "page_bank": None,
        "va_bank": None,
        "asid_bank": None,
    }

    if runner_kind == "mprv_bare":
        fields["slot_sensitive"] = True
        fields["page_bank"] = f"guard_bank{slot}"
        return fields

    if runner_kind == "real_mode" and access in {"load", "store", "amoadd"}:
        fields["slot_sensitive"] = True
        fields["page_bank"] = f"guard_bank{slot}"
        return fields

    if runner_kind == "fetch_basic" and translation == "bare":
        fields["slot_sensitive"] = True
        fields["page_bank"] = f"code_bank{slot}"
        return fields

    if translation == "sv39" or runner_kind in {
        "sv39_access",
        "tlb_access",
        "translated_side_effect",
        "store_stale",
        "fetch_stale",
        "sum_fetch",
    }:
        fields["slot_sensitive"] = True
        fields["va_bank"] = f"va_bank{slot}"

    if runner_kind in {"tlb_access", "store_stale", "fetch_stale", "sum_fetch"}:
        fields["slot_sensitive"] = True
        fields["asid_bank"] = f"asid_bank{slot}"

    return fields


def build_generated_case(
    *,
    params: dict[str, Any],
    index: int,
    name: str | None = None,
    seed: int = BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Build a v3 generated case from a scenario-parameter tuple.

    The case mirrors the catalog case shape so ``predict_shared56_bins`` and
    ``classify_scenario`` work unchanged.  The probe executes it through the
    parameterized case-runner (``runner_code``), not a phase function.
    """
    runner_kind = str(params.get("runner_kind") or "sv39_access")
    privilege = str(params.get("privilege") or "m").lower()
    effective = str(params.get("effective_privilege") or privilege).lower()
    access = str(params.get("access") or "load").lower()
    translation = str(params.get("translation") or "sv39").lower()
    pte_rwx = str(params.get("pte_rwx") or "rw-").lower()
    pte_user = bool(params.get("pte_user", False))
    pte_valid = bool(params.get("pte_valid", True))
    sum_enabled = bool(params.get("sum", False))
    mxr = bool(params.get("mxr", False))
    record = str(params.get("record") or f"gen-{index:04d}")
    case_name = name or f"{_GENERATED_PROFILE}__{record}"

    runner_code = GENERATED_RUNNER_CODES.get(runner_kind)
    if runner_code is None:
        raise ValueError(f"unknown generated runner_kind: {runner_kind!r}")
    if runner_kind == "mprv_bare":
        translation = "bare"
        pte_rwx, pte_user, pte_valid = "---", False, True
    parser = GENERATED_RUNNER_TO_PARSER[runner_kind]

    scenario_spec = {
        "schema_version": 3,
        "target": C910_NONPMP_TARGET,
        "profile": _GENERATED_PROFILE,
        "record": record,
        "runner_kind": runner_kind,
        "params": {
            "privilege": privilege,
            "effective_privilege": effective,
            "access": access,
            "translation": translation,
            "pte_rwx": pte_rwx,
            "pte_user": pte_user,
            "pte_valid": pte_valid,
            "sum": sum_enabled,
            "mxr": mxr,
        },
    }
    case = {
        "schema_version": 3,
        "target": C910_NONPMP_TARGET,
        "name": case_name,
        "seed": seed,
        "index": index,
        "profile": _GENERATED_PROFILE,
        "privilege": privilege,
        "access": access,
        "translation": translation,
        "mprv": bool(privilege == "m" and effective != "m"),
        "mpp": effective,
        "effective_privilege": effective,
        "sum_enabled": sum_enabled,
        "mxr": mxr,
        "sfence_vma": True,
        "ad_update_mode": "hardware",
        "mseccfg": {},
        "pmp_entries": [],
        "coverage_tags": ["generated", runner_kind, access, privilege, translation],
        "ptw_fault_level": None,
        "preload_mode": None,
        "pmp_match_mode": None,
        "pmp_match_result": None,
        "pmp_locked": None,
        "pmp_allow": None,
        "expected_allowed": True,
        "pte_permissions": {
            "rwx": pte_rwx,
            "user": pte_user,
            "accessed": True,
            "dirty": True,
            "valid": pte_valid,
        },
        "security_focus": f"generated:{runner_kind}",
        "smepmp_rule": None,
        "required_capabilities_override": [],
        "required_capabilities": [],
        "oracle_applicability": "valid",
        "uart_record": record,
        "uart_parser": parser,
        "scenario_spec": scenario_spec,
        "contract_trace": {},
        "expected": {"allowed": True, "trap_cause": None, "stage": "normal", "reason": "generated"},
        "stateful_sequence": None,
        "scenario_hash": _case_hash(scenario_spec),
        "runner_params": {
            "runner_kind": runner_kind,
            "phase": record,
            "slot": 0,
            "slot_sensitive": False,
            "page_bank": None,
            "va_bank": None,
            "asid_bank": None,
        },
        "generated_params": {
            "runner_kind": runner_kind,
            "runner_code": runner_code,
            "privilege": privilege,
            "effective_privilege": effective,
            "access": access,
            "translation": translation,
            "pte_rwx": pte_rwx,
            "pte_user": pte_user,
            "pte_valid": pte_valid,
            "sum": sum_enabled,
            "mxr": mxr,
        },
    }
    return case


def _case_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def default_pilot_case_names() -> list[str]:
    return list(DEFAULT_PILOT_CASE_NAMES)


def build_dynamic_manifest(
    *,
    case_names: list[str],
    campaign_id: str,
    round_id: str,
    selection_source: str = "bootstrap",
    estimated_new_bins_by_case: dict[str, int] | None = None,
    timebase_hz: int = DEFAULT_TIMEBASE_HZ,
    capability: dict[str, Any] | None = None,
    generated_cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a round manifest.

    Without ``generated_cases`` the manifest is schema v2 (catalog-only, executed
    by phase functions).  With ``generated_cases`` (list of cases built by
    ``build_generated_case``) the manifest is schema v3: generated entries carry
    the full ``params`` tuple + embedded ``case`` and are executed by the probe's
    parameterized case-runner (``runner_code``).  Base record names must be
    unique across all entries.
    """
    capability = capability or bootstrap_capability()
    catalog = {case["name"]: case for case in catalog_cases(capability=capability)}
    missing = [name for name in case_names if name not in catalog]
    if missing:
        raise ValueError(f"unknown C910 dynamic case(s): {missing}")
    estimated = estimated_new_bins_by_case or {}
    entries: list[dict[str, Any]] = []
    for index, case_name in enumerate(case_names):
        case = catalog[case_name]
        entries.append(
            {
                "case_id": case["name"],
                "name": case["name"],
                "profile": case["profile"],
                "record": case["uart_record"],
                "uart_parser": case["uart_parser"],
                "scenario_hash": case["scenario_hash"],
                "runner_params": dict(case.get("runner_params") or {}),
                "selection_source": selection_source,
                "estimated_new_bins": int(estimated.get(case_name, 0)),
                "selected_index": index,
            }
        )
    generated = list(generated_cases or [])
    for index, case in enumerate(generated, start=len(entries)):
        gparams = dict(case.get("generated_params") or {})
        entries.append(
            {
                "case_id": case["name"],
                "name": case["name"],
                "profile": case["profile"],
                "record": case["uart_record"],
                "uart_parser": case["uart_parser"],
                "scenario_hash": case["scenario_hash"],
                "runner_params": dict(case.get("runner_params") or {}),
                "params": gparams,
                "runner_code": int(gparams.get("runner_code") or 0),
                "predicted_bins": list(case.get("predicted_bins") or []),
                "selection_source": selection_source,
                "estimated_new_bins": int(estimated.get(case["name"], 0)),
                "selected_index": index,
                "case": case,
            }
        )
    records = [str(entry["record"]) for entry in entries]
    if len(records) != len(set(records)):
        raise ValueError("dynamic manifest requires unique base records per round")
    manifest = {
        "schema_version": (
            GENERATED_MANIFEST_SCHEMA_VERSION if generated else DYNAMIC_MANIFEST_SCHEMA_VERSION
        ),
        "target": C910_NONPMP_TARGET,
        "dut": C910_NONPMP_DUT,
        "capability_profile": C910_NONPMP_CAPABILITY_PROFILE,
        "campaign_id": str(campaign_id),
        "round_id": str(round_id),
        "selection_source": str(selection_source),
        "timebase_hz": int(timebase_hz),
        "catalog_case_count": len(catalog),
        "generated_case_count": len(generated),
        "case_count": len(entries),
        "entries": entries,
    }
    manifest["sha256"] = _stable_hash(
        {
            key: value
            for key, value in manifest.items()
            if key != "sha256"
        }
    )
    return manifest


def write_dynamic_manifest(
    *,
    out_json: Path,
    out_c: Path | None,
    case_names: list[str],
    campaign_id: str,
    round_id: str,
    selection_source: str = "bootstrap",
    estimated_new_bins_by_case: dict[str, int] | None = None,
    timebase_hz: int = DEFAULT_TIMEBASE_HZ,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = build_dynamic_manifest(
        case_names=case_names,
        campaign_id=campaign_id,
        round_id=round_id,
        selection_source=selection_source,
        estimated_new_bins_by_case=estimated_new_bins_by_case,
        timebase_hz=timebase_hz,
        capability=capability,
    )
    write_json(Path(out_json), manifest)
    if out_c is not None:
        Path(out_c).write_text(generated_manifest_source(manifest), encoding="ascii")
    return manifest


def generated_manifest_source(manifest: dict[str, Any]) -> str:
    entries = list(manifest.get("entries") or [])
    lines = [
        "/*",
        " * SPDX-License-Identifier: BSD-2-Clause",
        " *",
        " * Auto-generated by pmpfuzz.c910_nonpmp_dynamic.",
        " */",
        "",
        "#include <sbi/sbi_console.h>",
        "#include <sbi/sbi_types.h>",
        "",
        '#define C910_NONPMP_TAG "[nonpmp-chain] "',
        "",
        "struct c910_nonpmp_case_params {",
        "\tulong runner_code;",
        "\tulong mpp;",
        "\tulong access;",
        "\tulong translation;",
        "\tulong pte_rwx;",
        "\tulong pte_user;",
        "\tulong pte_valid;",
        "\tulong sum;",
        "\tulong mxr;",
        "};",
        "struct c910_nonpmp_case_entry {",
        "\tconst char *case_name;",
        "\tconst char *record;",
        "\tconst char *scenario_hash;",
        "\tconst char *runner_kind;",
        "\tconst char *phase;",
        "\tulong slot;",
        "\tstruct c910_nonpmp_case_params params;",
        "};",
        "",
        "static const struct c910_nonpmp_case_entry c910_selected_cases[] = {",
    ]
    for entry in entries:
        runner_params = dict(entry.get("runner_params") or {})
        lines.append(
            '\t{"%s", "%s", "%s", "%s", "%s", %dUL, %s},'
            % (
                _c_escape(str(entry["case_id"])),
                _c_escape(str(entry["record"])),
                _c_escape(str(entry["scenario_hash"])),
                _c_escape(str(runner_params.get("runner_kind") or "")),
                _c_escape(str(runner_params.get("phase") or "")),
                int(runner_params.get("slot") or 0),
                _params_c_initializer(entry),
            )
        )
    lines.extend(
        [
            "};",
            "",
            "static int c910_nonpmp_streq(const char *lhs, const char *rhs)",
            "{",
            "\tif (!lhs || !rhs)",
            "\t\treturn 0;",
            "\twhile (*lhs && *rhs && *lhs == *rhs) {",
            "\t\tlhs++;",
            "\t\trhs++;",
            "\t}",
            "\treturn *lhs == *rhs;",
            "}",
            "",
            "const char *c910_nonpmp_manifest_campaign_id(void)",
            "{",
            '\treturn "%s";' % _c_escape(str(manifest["campaign_id"])),
            "}",
            "",
            "const char *c910_nonpmp_manifest_round_id(void)",
            "{",
            '\treturn "%s";' % _c_escape(str(manifest["round_id"])),
            "}",
            "",
            "const char *c910_nonpmp_manifest_sha256(void)",
            "{",
            '\treturn "%s";' % _c_escape(str(manifest["sha256"])),
            "}",
            "",
            "ulong c910_nonpmp_manifest_schema_version(void)",
            "{",
            "\treturn %dUL;" % int(manifest.get("schema_version") or 0),
            "}",
            "",
            "ulong c910_nonpmp_manifest_case_count(void)",
            "{",
            "\treturn %dUL;" % int(manifest.get("case_count") or 0),
            "}",
            "",
            "const struct c910_nonpmp_case_entry *c910_nonpmp_manifest_case_at(ulong index)",
            "{",
            "\tif (index >= %dUL)" % len(entries),
            "\t\treturn 0;",
            "\treturn &c910_selected_cases[index];",
            "}",
            "",
            "int c910_nonpmp_record_selected(const char *record)",
            "{",
            "\tunsigned long index;",
            "",
            "\tif (!record)",
            "\t\treturn 0;",
            "\tfor (index = 0; index < %dUL; index++) {" % len(entries),
            "\t\tif (c910_nonpmp_streq(record, c910_selected_cases[index].record))",
            "\t\t\treturn 1;",
            "\t}",
            "\treturn 0;",
            "}",
            "",
            "int c910_nonpmp_case_selected(const char *case_name)",
            "{",
            "\tunsigned long index;",
            "",
            "\tif (!case_name)",
            "\t\treturn 0;",
            "\tfor (index = 0; index < %dUL; index++) {" % len(entries),
            "\t\tif (c910_nonpmp_streq(case_name, c910_selected_cases[index].case_name))",
            "\t\t\treturn 1;",
            "\t}",
            "\treturn 0;",
            "}",
            "",
            "const char *c910_nonpmp_case_name_for_record(const char *record)",
            "{",
            "\tunsigned long index;",
            "",
            "\tif (!record)",
            '\t\treturn "";',
            "\tfor (index = 0; index < %dUL; index++) {" % len(entries),
            "\t\tif (c910_nonpmp_streq(record, c910_selected_cases[index].record))",
            "\t\t\treturn c910_selected_cases[index].case_name;",
            "\t}",
            '\treturn "";',
            "}",
            "",
            "const char *c910_nonpmp_scenario_hash_for_record(const char *record)",
            "{",
            "\tunsigned long index;",
            "",
            "\tif (!record)",
            '\t\treturn "";',
            "\tfor (index = 0; index < %dUL; index++) {" % len(entries),
            "\t\tif (c910_nonpmp_streq(record, c910_selected_cases[index].record))",
            "\t\t\treturn c910_selected_cases[index].scenario_hash;",
            "\t}",
            '\treturn "";',
            "}",
            "",
            "void c910_nonpmp_generated_manifest(void)",
            "{",
            '\tsbi_printf(C910_NONPMP_TAG "manifest campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s\\n",',
            "\t\t   c910_nonpmp_manifest_campaign_id(),",
            "\t\t   c910_nonpmp_manifest_round_id(),",
            "\t\t   c910_nonpmp_manifest_case_count(),",
            "\t\t   c910_nonpmp_manifest_sha256());",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def parse_case_timings(text: str) -> dict[str, dict[str, Any]]:
    starts: dict[str, dict[str, Any]] = {}
    timings: dict[str, dict[str, Any]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        begin = _CASE_BEGIN_RE.search(line)
        if begin:
            starts[str(begin.group("case_id"))] = {
                "case_id": str(begin.group("case_id")),
                "record": str(begin.group("record")),
                "scenario_hash": str(begin.group("scenario_hash")),
                "start_ticks": int(begin.group("start_ticks")),
            }
            continue
        end = _CASE_END_RE.search(line)
        if not end:
            continue
        case_id = str(end.group("case_id"))
        start = starts.get(case_id)
        timings[case_id] = {
            "case_id": case_id,
            "record": str(end.group("record")),
            "scenario_hash": str(end.group("scenario_hash")),
            "start_ticks": int(start.get("start_ticks")) if start else None,
            "end_ticks": int(end.group("end_ticks")),
            "elapsed_ticks": int(end.group("elapsed_ticks")),
        }
    return timings


def write_dynamic_run(
    *,
    uart_log: Path,
    manifest_path: Path,
    out_dir: Path,
    capability: dict[str, Any] | None = None,
    freeze_universe: bool = True,
) -> dict[str, str]:
    uart_log = Path(uart_log)
    manifest_path = Path(manifest_path)
    out_dir = Path(out_dir)
    capability = capability or bootstrap_capability(path=str(uart_log))
    manifest = _load_dynamic_manifest(manifest_path)
    catalog = {case["name"]: case for case in catalog_cases(capability=capability)}

    text = uart_log.read_text(encoding="utf-8", errors="replace")
    records = parse_uart_records(text)
    timings = parse_case_timings(text)
    cases = []
    for entry in manifest["entries"]:
        if "case" in entry:
            cases.append(entry["case"])
        else:
            cases.append(catalog[str(entry["case_id"])])

    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    results_dir = out_dir / "results"
    artifacts_dir = out_dir / "artifacts"
    manifests_dir = out_dir / "manifests"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    copied_uart = artifacts_dir / "uart.log"
    copied_uart.write_text(text, encoding="utf-8")
    copied_manifest = manifests_dir / "round_manifest.json"
    copied_manifest.parent.mkdir(parents=True, exist_ok=True)
    copied_manifest.write_text(manifest_path.read_text(encoding="ascii"), encoding="ascii")

    write_json(
        out_dir / "run.json",
        {
            "mode": "c910-nonpmp-dynamic-analysis",
            "target": C910_NONPMP_TARGET,
            "dut": C910_NONPMP_DUT,
            "seed": BOOTSTRAP_SEED,
            "case_count": len(cases),
            "catalog_case_count": int(manifest["catalog_case_count"]),
            "uart_log": str(copied_uart),
            "round_manifest": str(copied_manifest),
        },
    )
    write_json(
        out_dir / "dut_capabilities.json",
        {
            "schema_version": capability["schema_version"],
            "duts": {C910_NONPMP_DUT: capability},
        },
    )

    universes = None
    if freeze_universe:
        universes = _freeze_dynamic_universes(capability=capability)
        write_coverage_universes(manifests_dir / "coverage_universes", universes)

    results_by_name: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_dir = cases_dir / case["name"]
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "case.json", case)

        record = records.get(str(case["uart_record"]))
        timing = timings.get(str(case["name"]))
        result_payload = _dynamic_result_from_case(
            case=case,
            record=record,
            log_path=copied_uart,
            timing=timing,
            timebase_hz=int(manifest["timebase_hz"]),
        )
        result_dir = results_dir / case["name"]
        result_dir.mkdir(parents=True, exist_ok=True)
        write_json(result_dir / "result.json", result_payload)
        results_by_name[str(case["name"])] = result_payload

    _write_dynamic_timeline(
        out_dir=out_dir,
        manifest=manifest,
        capability=capability,
        cases=cases,
        results_by_name=results_by_name,
        timings=timings,
        universes=universes,
    )

    write_aggregate(out_dir)
    coverage_path = write_coverage(out_dir)
    triage_run(out_dir)
    report_path = write_report(out_dir)
    return {
        "dut": C910_NONPMP_DUT,
        "run_dir": str(out_dir),
        "coverage": str(coverage_path),
        "report": str(report_path),
        "uart_copy": str(copied_uart),
        "manifest_copy": str(copied_manifest),
    }


def _freeze_dynamic_universes(*, capability: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from .coverage_universe import make_coverage_universe

    targets = compute_coverage_targets(
        target=C910_NONPMP_TARGET,
        capability=capability,
        include_experimental=False,
        seed=BOOTSTRAP_SEED,
    )
    fingerprint = str(targets["capability_fingerprint"])
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=targets["semantic"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=C910_NONPMP_TARGET,
            include_experimental=False,
            generator_seed=BOOTSTRAP_SEED,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=targets["pairwise"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=C910_NONPMP_TARGET,
            include_experimental=False,
            generator_seed=BOOTSTRAP_SEED,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=targets["security_triples"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=C910_NONPMP_TARGET,
            include_experimental=False,
            generator_seed=BOOTSTRAP_SEED,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=targets["predicates"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=C910_NONPMP_TARGET,
            include_experimental=False,
            generator_seed=BOOTSTRAP_SEED,
        ),
    }


def _dynamic_result_from_case(
    *,
    case: dict[str, Any],
    record: dict[str, Any] | None,
    log_path: Path,
    timing: dict[str, Any] | None,
    timebase_hz: int,
) -> dict[str, Any]:
    payload = _result_from_case(case, record, log_path)
    if timing is None:
        return payload
    elapsed_ticks = int(timing.get("elapsed_ticks") or 0)
    payload["elapsed_seconds"] = elapsed_ticks / float(timebase_hz)
    payload["elapsed_ticks"] = elapsed_ticks
    payload["case_start_ticks"] = timing.get("start_ticks")
    payload["case_end_ticks"] = timing.get("end_ticks")
    payload["observed_scenario_hash"] = timing.get("scenario_hash")
    return payload


def _write_dynamic_timeline(
    *,
    out_dir: Path,
    manifest: dict[str, Any],
    capability: dict[str, Any],
    cases: list[dict[str, Any]],
    results_by_name: dict[str, dict[str, Any]],
    timings: dict[str, dict[str, Any]],
    universes: dict[str, dict[str, Any]] | None,
) -> None:
    targets = compute_coverage_targets(
        target=C910_NONPMP_TARGET,
        capability=capability,
        include_experimental=False,
        seed=BOOTSTRAP_SEED,
    )
    recorder = TimelineRecorder(
        run_dir=out_dir,
        campaign_id=str(manifest["campaign_id"]),
        variant="dynamic-pilot",
        dut=C910_NONPMP_DUT,
        seed=BOOTSTRAP_SEED,
        target_semantic=set(targets["semantic"]["target_bins"]),
        target_pairwise=set(targets["pairwise"]["target_bins"]),
        target_security_triples=set(targets["security_triples"]["target_bins"]),
        target_predicates=set(targets["predicates"]["target_bins"]),
    )
    recorder.write_metadata(
        coverage_mode="semantic",
        round_size=int(manifest["case_count"]),
        per_case_timeout_seconds=10,
        extra={
            "run_class": "pilot",
            "driver_mode": "c910-nonpmp-dynamic-pilot",
            "round_id": str(manifest["round_id"]),
            "round_manifest_sha256": str(manifest["sha256"]),
            "timebase_hz": int(manifest["timebase_hz"]),
            "coverage_universe_hashes": (
                {mode: universe["sha256"] for mode, universe in universes.items()}
                if universes is not None
                else {}
            ),
        },
    )
    ordered = _timeline_order(cases=cases, timings=timings)
    wall_seconds = 0.0
    for case in ordered:
        result = results_by_name[str(case["name"])]
        timing = timings.get(str(case["name"])) or {}
        case_elapsed = float(result.get("elapsed_seconds") or 0.0)
        wall_seconds += case_elapsed
        completion_ticks = timing.get("end_ticks")
        recorder.record(
            case,
            result,
            elapsed_wall_seconds=wall_seconds,
            case_elapsed_seconds=case_elapsed,
            completion_monotonic_seconds=(
                None
                if completion_ticks is None
                else float(completion_ticks) / float(manifest["timebase_hz"])
            ),
        )


def _timeline_order(*, cases: list[dict[str, Any]], timings: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = []
    for index, case in enumerate(cases):
        timing = timings.get(str(case["name"])) or {}
        end_ticks = timing.get("end_ticks")
        indexed.append(
            (
                end_ticks if type(end_ticks) is int else 1 << 62,
                index,
                case,
            )
        )
    indexed.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in indexed]


def _load_dynamic_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(Path(path).read_text(encoding="ascii"))
    if int(manifest.get("schema_version") or 0) not in {
        DYNAMIC_MANIFEST_SCHEMA_VERSION,
        GENERATED_MANIFEST_SCHEMA_VERSION,
    }:
        raise ValueError(
            f"unsupported dynamic manifest schema_version {manifest.get('schema_version')!r}"
        )
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("dynamic manifest must contain a non-empty entries list")
    expected = manifest.get("sha256")
    actual = _stable_hash({key: value for key, value in manifest.items() if key != "sha256"})
    if expected != actual:
        raise ValueError(f"dynamic manifest sha256 mismatch: expected {expected}, got {actual}")
    return manifest


def _stable_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _params_c_initializer(entry: dict[str, Any]) -> str:
    """Render a manifest entry's params as a C struct initializer.

    Catalog (v2) entries have no params -> all-zero struct (runner_code 0 =
    phase-handled).  Generated (v3) entries carry the numeric-coded tuple that
    the probe's parameterized case-runner reads.
    """
    params = dict(entry.get("params") or {})
    code = int(params.get("runner_code") or 0)
    if code == 0:
        return "{0, 0, 0, 0, 0, 0, 0, 0, 0}"
    privilege = str(params.get("privilege") or "m").lower()
    effective = str(params.get("effective_privilege") or privilege).lower()
    access = str(params.get("access") or "load").lower()
    translation = str(params.get("translation") or "bare").lower()
    rwx = str(params.get("pte_rwx") or "---").lower()
    mpp = _PRIV_CODE.get(effective, 0)
    acc = _ACCESS_CODE.get(access, 0)
    trans = _TRANS_CODE.get(translation, 0)
    pte_rwx = sum(_RWX_CODE.get(char, 0) for char in rwx)
    user = 1 if bool(params.get("pte_user")) else 0
    valid = 1 if bool(params.get("pte_valid")) else 0
    s = 1 if bool(params.get("sum")) else 0
    mx = 1 if bool(params.get("mxr")) else 0
    return "{%d, %d, %d, %d, %d, %d, %d, %d, %d}" % (
        code, mpp, acc, trans, pte_rwx, user, valid, s, mx,
    )


def _c_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
