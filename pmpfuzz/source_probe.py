from __future__ import annotations

import difflib
import shlex
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from .schema import write_json


@dataclass(frozen=True)
class SourceProbeSpec:
    probe_id: str
    dut: str
    security_chain: str
    purpose: str
    path_candidates: tuple[str, ...]
    patterns: tuple[str, ...]
    signal_keys: tuple[str, ...]
    instrumentation_hint: str
    expand_all_candidates: bool = False


def default_source_probe_specs() -> tuple[SourceProbeSpec, ...]:
    return (
        SourceProbeSpec(
            probe_id="xiangshan_pmp_checker",
            dut="xiangshan-clean",
            security_chain="pmp-check",
            purpose="Observe native XiangShan PMP hit/permission decisions.",
            path_candidates=("src/main/scala/xiangshan/backend/fu/PMP.scala",),
            patterns=("class PMP", "PMPChecker", "pmp_hit", "PMPEntry"),
            signal_keys=("stage", "addr", "allow", "match", "priv", "access"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=xiangshan-clean probe=xiangshan_pmp_checker '
                'chain=pmp-check stage=%s addr=0x%x allow=%d match=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="xiangshan_l1_tlb_exception",
            dut="xiangshan-clean",
            security_chain="exception-arbitration",
            purpose="Observe L1 TLB page/access fault arbitration around PMP and PTW results.",
            path_candidates=("src/main/scala/xiangshan/cache/mmu/TLB.scala",),
            patterns=("ptw", "exception", "pageFault", "accessFault"),
            signal_keys=("stage", "level", "cause", "pf", "af", "addr"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=xiangshan-clean probe=xiangshan_l1_tlb_exception '
                'chain=exception-arbitration stage=%s level=%s cause=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="xiangshan_l2tlb_ptw_request",
            dut="xiangshan-clean",
            security_chain="ptw-request",
            purpose="Observe L2TLB/PTW request and refill activity for PMP-denied walk pages.",
            path_candidates=(
                "src/main/scala/xiangshan/cache/mmu/L2TLB.scala",
                "src/main/scala/xiangshan/cache/mmu/L2TLBMissQueue.scala",
            ),
            patterns=("ptw_req", "ptw", "miss", "refill"),
            signal_keys=("stage", "level", "addr", "request", "response"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=xiangshan-clean probe=xiangshan_l2tlb_ptw_request '
                'chain=ptw-request stage=ptw level=%s paddr=0x%x\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="xiangshan_pmp_csr",
            dut="xiangshan-clean",
            security_chain="pmp-csr",
            purpose="Observe pmpcfg/pmpaddr lock and WARL state that controls effective PMP rules.",
            path_candidates=(
                "src/main/scala/xiangshan/backend/fu/NewCSR/CSRPMP.scala",
                "src/main/scala/xiangshan/backend/fu/NewCSR/PMPEntryModule.scala",
            ),
            patterns=("pmpcfg", "pmpaddr", "locked", "Lock"),
            signal_keys=("entry", "cfg", "addr", "locked"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=xiangshan-clean probe=xiangshan_pmp_csr '
                'chain=pmp-csr entry=%d cfg=0x%x locked=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="boom_lsu_tlb_pmp_check",
            dut="boom-clean",
            security_chain="pmp-check",
            purpose="Observe BOOM LSU TLB PMPChecker inputs for final and PTW requests.",
            path_candidates=(
                "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "generators/boom/src/main/scala/v4/lsu/tlb.scala",
            ),
            patterns=("Module(new PMPChecker", "pmp(w).io", "pmp.io"),
            signal_keys=("stage", "addr", "allow", "match", "priv", "access"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check '
                'schema=2 role=diagnostic chain=pmp-check stage=%s addr=0x%x\\n", ...)'
            ),
            expand_all_candidates=True,
        ),
        SourceProbeSpec(
            probe_id="boom_ptw_response_ae",
            dut="boom-clean",
            security_chain="ptw-response",
            purpose="Observe whether BOOM receives and stores PTW access-fault metadata.",
            path_candidates=(
                "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "generators/boom/src/main/scala/v4/lsu/tlb.scala",
            ),
            patterns=("io.ptw.resp.bits.ae_final", "newEntry.ae", "ae_final"),
            signal_keys=("stage", "level", "ae_final", "addr"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae '
                'schema=2 role=diagnostic chain=ptw-response stage=ptw level=%s ae_final=%d\\n", ...)'
            ),
            expand_all_candidates=True,
        ),
        SourceProbeSpec(
            probe_id="boom_ptw_ae_array",
            dut="boom-clean",
            security_chain="exception-arbitration",
            purpose="Observe BOOM ptw_ae_array masking of page faults versus access faults.",
            path_candidates=(
                "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "generators/boom/src/main/scala/v4/lsu/tlb.scala",
            ),
            patterns=("ptw_ae_array", "pf_ld_array", "pf_st_array", "pf_inst_array"),
            signal_keys=("stage", "cause", "ptw_ae", "pf", "af"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array '
                'schema=2 role=diagnostic chain=exception-arbitration stage=%s cause=%d ptw_ae=%d\\n", ...)'
            ),
            expand_all_candidates=True,
        ),
        SourceProbeSpec(
            probe_id="boom_ptw_request",
            dut="boom-clean",
            security_chain="ptw-request",
            purpose="Observe BOOM PTW request address and replay/refill state.",
            path_candidates=(
                "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "generators/boom/src/main/scala/v4/lsu/tlb.scala",
            ),
            patterns=("io.ptw.req.bits.bits.addr", "io.ptw.req.valid", "do_refill"),
            signal_keys=("stage", "addr", "refill", "valid"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_request '
                'schema=2 role=diagnostic chain=ptw-request stage=ptw paddr=0x%x refill=%d\\n", ...)'
            ),
            expand_all_candidates=True,
        ),
        SourceProbeSpec(
            probe_id="boom_target_operation_runtime",
            dut="boom-clean",
            security_chain="target-operation-runtime",
            purpose="Observe BOOM target load/store completion or trap with actual PC and address.",
            path_candidates=(
                "generators/boom/src/main/scala/v3/lsu/lsu.scala",
                "generators/boom/src/main/scala/v4/lsu/lsu.scala",
            ),
            patterns=("MEMTRACE_PRINTF", "commit_store", "commit_load", "mem_xcpt_valids"),
            signal_keys=("status", "pc", "addr", "access", "size", "mcause", "mtval"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime '
                'schema=cascade-target-operation-v1 role=runtime chain=target-operation '
                'status=%s pc=0x%x addr=0x%x access=%s size=%d\\n", ...)'
            ),
            expand_all_candidates=True,
        ),
        SourceProbeSpec(
            probe_id="rocket_pmp_checker",
            dut="rocket-clean",
            security_chain="pmp-check",
            purpose="Observe Rocket PMPChecker inputs and first-match permission decision.",
            path_candidates=("generators/rocket-chip/src/main/scala/rocket/PMP.scala",),
            patterns=("class PMPChecker", "PMPChecker", "pmpcfg", "pmpaddr"),
            signal_keys=("stage", "addr", "allow", "match", "priv", "access"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker '
                'chain=pmp-check stage=%s addr=0x%x access=%s allow=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="rocket_ptw_access_exception",
            dut="rocket-clean",
            security_chain="ptw-response",
            purpose="Observe Rocket PTW access-fault separation from final access fault.",
            path_candidates=("generators/rocket-chip/src/main/scala/rocket/PTW.scala",),
            patterns=("ae_ptw", "ae_final", "resp", "access exception"),
            signal_keys=("stage", "level", "ae_ptw", "ae_final", "addr"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception '
                'chain=ptw-response stage=ptw level=%s ae_ptw=%d ae_final=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="rocket_tlb_exception_arbitration",
            dut="rocket-clean",
            security_chain="exception-arbitration",
            purpose="Observe Rocket TLB exception priority and ptw_ae_array page-fault masking.",
            path_candidates=("generators/rocket-chip/src/main/scala/rocket/TLB.scala",),
            patterns=("ptw_ae_array", "pf_ld", "af_ld", "ae_ld", "pageFault"),
            signal_keys=("stage", "cause", "ptw_ae", "pf", "af"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_exception_arbitration '
                'chain=exception-arbitration stage=%s cause=%d ptw_ae=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="rocket_tlb_permissions",
            dut="rocket-clean",
            security_chain="tlb-permission",
            purpose="Observe Rocket final TLB permission matrix for SUM/MXR/user execute/load/store.",
            path_candidates=("generators/rocket-chip/src/main/scala/rocket/TLBPermissions.scala",),
            patterns=("class TLBPermissions", "sr_mxr", "sr_sum", "prv"),
            signal_keys=("priv", "access", "mxr", "sum", "allow"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_permissions '
                'chain=tlb-permission priv=%s access=%s mxr=%d sum=%d allow=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_pmp_csr_state",
            dut="cva6-clean",
            security_chain="pmp-csr",
            purpose="Observe CVA6 PMP CSR state that controls pmpcfg/pmpaddr effective rules.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
            ),
            patterns=("pmpcfg_o", "pmpaddr_o", "pmpcfg_q", "pmpaddr_q"),
            signal_keys=("entry", "cfg", "addr", "locked"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_pmp_csr_state '
                'chain=pmp-csr entry=%d cfg=0x%x addr=0x%x\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_ptw_pmp_check",
            dut="cva6-clean",
            security_chain="pmp-check",
            purpose="Observe CVA6 PTW PMP allow/deny decisions at the page-table walk access point.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("allow_access", "data_rvalid_q", "ptw_pptr_q"),
            signal_keys=("stage", "addr", "allow", "priv", "access", "size"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_pmp_check '
                'schema=2 role=diagnostic chain=pmp-check stage=ptw addr=0x%x prv=%d access=load allow=%d size=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_mmu_pmp_check",
            dut="cva6-clean",
            security_chain="pmp-check",
            purpose="Observe CVA6 final fetch/load/store PMP allow/deny decisions at the MMU interface.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("pmp_instr_allow", "i_pmp_if", "pmp_data_allow", "i_pmp_data"),
            signal_keys=("stage", "addr", "allow", "priv", "access"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check '
                'schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%x prv=%d access=load allow=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_ptw_exception",
            dut="cva6-clean",
            security_chain="ptw-response",
            purpose="Observe CVA6 PTW/TLB access exceptions that decide page-walk PMP outcomes.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("ptw", "access_exception", "exception_o", "ptw_access_exception_o"),
            signal_keys=("stage", "level", "vaddr", "addr", "allow", "exception"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception '
                'schema=2 role=diagnostic chain=ptw-response stage=ptw level=%d '
                'vaddr=0x%x paddr=0x%x allow=%d exception=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_tlb_exception_arbitration",
            dut="cva6-clean",
            security_chain="exception-arbitration",
            purpose="Observe CVA6 TLB exception priority around page/access faults and sfence flushes.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("tlb", "exception", "flush_tlb", "access_exception", "flush_i", "lu_hit_o"),
            signal_keys=("stage", "cause", "pf", "af", "flush"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration '
                'schema=2 role=diagnostic chain=exception-arbitration stage=%s cause=%d af=%d pf=%d\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_target_operation_issue",
            dut="cva6-clean",
            security_chain="target-operation-runtime",
            purpose="Observe CVA6 target load/store issue with the selected PC and transaction id.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ariane.sv",
            ),
            patterns=("pc_id_ex", "load_valid_ex_id", "store_valid_ex_id", "load_trans_id_ex_id"),
            signal_keys=("phase", "pc", "access", "trans_id"),
            instrumentation_hint=(
                '$display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue '
                'schema=cascade-target-operation-v1 role=runtime chain=target-operation '
                'phase=issue access=%s trans_id=%0d pc=0x%0h", ...);'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_target_operation_runtime",
            dut="cva6-clean",
            security_chain="target-operation-runtime",
            purpose="Observe CVA6 target load/store completion or trap with transaction id and actual address.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/load_store_unit.sv",
            ),
            patterns=("load_valid_o", "store_valid_o", "mmu_paddr", "mmu_exception"),
            signal_keys=("status", "access", "trans_id", "addr", "mcause", "mtval"),
            instrumentation_hint=(
                '$display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime '
                'schema=cascade-target-operation-v1 role=runtime chain=target-operation '
                'status=%s access=%s trans_id=%0d addr=0x%0h mcause=%0d mtval=0x%0h", ...);'
            ),
        ),
    )


def discover_source_probes(
    duts: Iterable[str],
    *,
    roots: Mapping[str, Path | str | None] | None = None,
    specs: Iterable[SourceProbeSpec] | None = None,
) -> dict[str, Any]:
    requested = tuple(dict.fromkeys(dut.strip() for dut in duts if dut.strip()))
    root_map = {key: Path(value) for key, value in (roots or {}).items() if value is not None}
    selected: list[SourceProbeSpec] = []
    for spec in (specs or default_source_probe_specs()):
        if spec.dut not in requested:
            continue
        if spec.expand_all_candidates and len(spec.path_candidates) > 1:
            selected.extend(
                replace(spec, path_candidates=(candidate,))
                for candidate in spec.path_candidates
            )
        else:
            selected.append(spec)
    probes = [_discover_one(spec, root_map.get(spec.dut)) for spec in selected]
    statuses: dict[str, int] = {}
    for probe in probes:
        status = str(probe["status"])
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "schema_version": 1,
        "provider": "source-probe",
        "duts": list(requested),
        "roots": {dut: str(root_map[dut]) for dut in sorted(root_map)},
        "summary": {
            "total": len(probes),
            "source_found": statuses.get("source_found", 0),
            "pattern_missing": statuses.get("pattern_missing", 0),
            "source_missing": statuses.get("source_missing", 0),
            "root_missing": statuses.get("root_missing", 0),
            "statuses": statuses,
        },
        "probes": probes,
    }


def write_source_probe_manifest(
    duts: Iterable[str],
    *,
    roots: Mapping[str, Path | str | None] | None,
    out_dir: Path,
) -> Path:
    manifest = discover_source_probes(duts, roots=roots)
    out = Path(out_dir) / "source_probe_manifest.json"
    write_json(out, manifest)
    return out


def build_source_probe_instrumentation(
    duts: Iterable[str],
    *,
    roots: Mapping[str, Path | str | None] | None = None,
    specs: Iterable[SourceProbeSpec] | None = None,
) -> dict[str, Any]:
    manifest = discover_source_probes(duts, roots=roots, specs=specs)
    changed_files: dict[tuple[str, str], dict[str, Any]] = {}
    current_text: dict[tuple[str, str], str] = {}
    probes: list[dict[str, Any]] = []

    for probe in manifest["probes"]:
        key = _probe_file_key(probe)
        result = _instrument_probe(probe, source_text=current_text.get(key) if key else None)
        probes.append(result["probe"])
        if result["after"] is None:
            continue
        root = str(result["probe"]["root"])
        relative_path = str(result["probe"]["relative_path"])
        key = (root, relative_path)
        previous = changed_files.get(key)
        current_text[key] = result["after"]
        changed_files[key] = {
            "root": root,
            "relative_path": relative_path,
            "before": previous["before"] if previous else result["before"],
            "after": result["after"],
            "probe_ids": sorted(set((previous or {}).get("probe_ids", []) + [str(probe["probe_id"])])),
        }

    patch_groups: list[dict[str, Any]] = []
    for index, root in enumerate(sorted({key[0] for key in changed_files}), 1):
        files = [change for key, change in sorted(changed_files.items()) if key[0] == root]
        patch_name = f"{_safe_patch_name(Path(root).name or f'root{index}')}.patch"
        patch_groups.append(
            {
                "root": root,
                "patch_file": f"patches/{patch_name}",
                "changed_files": [file["relative_path"] for file in files],
                "probe_ids": sorted({probe_id for file in files for probe_id in file["probe_ids"]}),
                "diff": "".join(_unified_diff(file["relative_path"], file["before"], file["after"]) for file in files),
            }
        )

    statuses: dict[str, int] = {}
    for probe in probes:
        status = str(probe["status"])
        statuses[status] = statuses.get(status, 0) + 1

    return {
        "schema_version": 1,
        "provider": "source-probe-instrumentation",
        "source_manifest": manifest,
        "summary": {
            "total": len(probes),
            "instrumented": statuses.get("instrumented", 0),
            "already_instrumented": statuses.get("already_instrumented", 0),
            "stale_instrumentation": statuses.get("stale_instrumentation", 0),
            "unsupported_template": statuses.get("unsupported_template", 0),
            "anchor_missing": statuses.get("anchor_missing", 0),
            "source_unavailable": statuses.get("source_unavailable", 0),
            "statuses": statuses,
            "patch_count": len(patch_groups),
        },
        "probes": probes,
        "patches": [
            {key: value for key, value in patch.items() if key != "diff"}
            for patch in patch_groups
        ],
        "_patch_diffs": {patch["patch_file"]: patch["diff"] for patch in patch_groups},
    }


def write_source_probe_instrumentation(
    duts: Iterable[str],
    *,
    roots: Mapping[str, Path | str | None] | None,
    out_dir: Path,
    specs: Iterable[SourceProbeSpec] | None = None,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    payload = build_source_probe_instrumentation(duts, roots=roots, specs=specs)
    patch_diffs = dict(payload.pop("_patch_diffs"))
    for relative_patch, diff_text in patch_diffs.items():
        patch_path = out_dir / relative_patch
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_text(diff_text, encoding="ascii")
    _write_apply_script(out_dir, payload["patches"])
    write_json(out_dir / "source_probe_instrumentation.json", payload)
    return payload


def _discover_one(spec: SourceProbeSpec, root: Path | None) -> dict[str, Any]:
    base = _spec_payload(spec)
    if root is None:
        return {
            **base,
            "status": "root_missing",
            "root": None,
            "file": None,
            "line": None,
            "matched_pattern": None,
            "matched_text": None,
        }
    for candidate in spec.path_candidates:
        path = root / candidate
        if not path.exists():
            continue
        match = _first_pattern_match(path, spec.patterns)
        if match is not None:
            line_number, pattern, text = match
            return {
                **base,
                "status": "source_found",
                "root": str(root),
                "file": str(path),
                "relative_path": candidate,
                "line": line_number,
                "matched_pattern": pattern,
                "matched_text": text,
            }
        return {
            **base,
            "status": "pattern_missing",
            "root": str(root),
            "file": str(path),
            "relative_path": candidate,
            "line": None,
            "matched_pattern": None,
            "matched_text": None,
        }
    return {
        **base,
        "status": "source_missing",
        "root": str(root),
        "file": None,
        "relative_path": None,
        "line": None,
        "matched_pattern": None,
        "matched_text": None,
    }


def _spec_payload(spec: SourceProbeSpec) -> dict[str, Any]:
    payload = asdict(spec)
    payload["path_candidates"] = list(spec.path_candidates)
    payload["patterns"] = list(spec.patterns)
    payload["signal_keys"] = list(spec.signal_keys)
    return payload


def _first_pattern_match(path: Path, patterns: tuple[str, ...]) -> tuple[int, str, str] | None:
    lowered_patterns = [(pattern, pattern.lower()) for pattern in patterns]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line_number, line in enumerate(lines, 1):
        lower_line = line.lower()
        for original, lowered in lowered_patterns:
            if lowered in lower_line:
                return line_number, original, line.strip()[:220]
    return None


def _probe_file_key(probe: Mapping[str, Any]) -> tuple[str, str] | None:
    if probe.get("status") != "source_found" or not probe.get("root") or not probe.get("relative_path"):
        return None
    return (str(probe["root"]), str(probe["relative_path"]))


_PROBE_SCHEMA_TOKENS: dict[str, tuple[str, ...]] = {
    "rocket_pmp_checker": ("schema=2", "stage=", "access=", "allow="),
    "rocket_ptw_access_exception": ("schema=3", "stage=ptw", "authoritative=1"),
    "rocket_tlb_exception_arbitration": ("schema=2", "stage=tlb"),
    "boom_lsu_tlb_pmp_check": ("schema=2", "role=diagnostic", "chain=pmp-check"),
    "boom_ptw_response_ae": ("schema=3", "role=diagnostic", "evidence=non_authoritative", "chain=ptw-response"),
    "boom_ptw_ae_array": ("schema=2", "role=diagnostic", "chain=exception-arbitration"),
    "boom_ptw_request": ("schema=3", "role=diagnostic", "evidence=non_authoritative", "chain=ptw-request"),
    "boom_target_operation_runtime": ("schema=cascade-target-operation-v1", "role=runtime", "chain=target-operation"),
    "cva6_ptw_pmp_check": ("schema=2", "role=diagnostic", "chain=pmp-check", "stage=ptw"),
    "cva6_mmu_pmp_check": ("schema=2", "role=diagnostic", "chain=pmp-check", "stage=final"),
    "cva6_ptw_exception": ("schema=2", "role=diagnostic", "chain=ptw-response", "stage=ptw"),
    "cva6_tlb_exception_arbitration": ("schema=2", "role=diagnostic", "chain=exception-arbitration", "stage=tlb"),
    "cva6_target_operation_issue": ("schema=cascade-target-operation-v1", "role=runtime", "chain=target-operation", "phase=issue"),
    "cva6_target_operation_runtime": ("schema=cascade-target-operation-v1", "role=runtime", "chain=target-operation", "status="),
}

_PROBE_FILE_TOKENS: dict[str, tuple[str, ...]] = {
    "boom_target_operation_runtime": ("pmpfuzz_runtime_uop", "phase=issue", "status=completed", "status=trap", "ldq_idx=%d", "stq_idx=%d"),
    "cva6_pmp_csr_state": ("pmpcfg_probe_seen_q", "pmpcfg_probe_prev_q", "pmpaddr_probe_prev_q"),
    "cva6_target_operation_issue": ("lsu_valid_id_ex && fu_data_id_ex.fu == LOAD", "lsu_valid_id_ex && fu_data_id_ex.fu == STORE", "fu_data_id_ex.trans_id"),
    "cva6_target_operation_runtime": ("pmpfuzz_load_paddr_o", "pmpfuzz_store_paddr_o", "assign pmpfuzz_load_paddr = ld_valid ? mmu_paddr : '0;", "assign pmpfuzz_store_paddr = st_valid ? mmu_paddr : '0;"),
}


def _instrument_probe(probe: Mapping[str, Any], *, source_text: str | None = None) -> dict[str, Any]:
    payload = {**probe}
    if probe.get("status") != "source_found" or not probe.get("file"):
        payload["status"] = "source_unavailable"
        payload["instrumentation_error"] = f"source discovery status is {probe.get('status')}"
        return {"probe": payload, "before": None, "after": None}

    file_path = Path(str(probe["file"]))
    if source_text is None:
        try:
            before = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            payload["status"] = "source_unavailable"
            payload["instrumentation_error"] = f"{type(exc).__name__}: {exc}"
            return {"probe": payload, "before": None, "after": None}
    else:
        before = source_text

    probe_id = str(probe["probe_id"])
    marker = f"PMFUZZ_PROBE dut={probe['dut']} probe={probe_id}"
    if marker in before:
        required_tokens = _PROBE_SCHEMA_TOKENS.get(probe_id)
        required_file_tokens = _PROBE_FILE_TOKENS.get(probe_id)
        marker_lines = [line for line in before.splitlines() if marker in line]
        marker_ok = not required_tokens or all(
            all(token in line for token in required_tokens) for line in marker_lines
        )
        file_ok = not required_file_tokens or all(token in before for token in required_file_tokens)
        if not marker_ok or not file_ok:
            contract_parts: list[str] = []
            if required_tokens:
                contract_parts.append(", ".join(required_tokens))
            if required_file_tokens:
                contract_parts.append(", ".join(required_file_tokens))
            payload["status"] = "stale_instrumentation"
            payload["instrumentation_error"] = (
                f"probe marker is present but does not satisfy the current contract: "
                f"{'; '.join(contract_parts)}; regenerate from a pristine pinned source tree"
            )
        else:
            payload["status"] = "already_instrumented"
            payload["instrumentation_error"] = None
        return {"probe": payload, "before": before, "after": None}

    instrumenter = _PROBE_INSTRUMENTERS.get(probe_id)
    if instrumenter is None:
        payload["status"] = "unsupported_template"
        payload["instrumentation_error"] = "no source instrumentation template for probe"
        return {"probe": payload, "before": before, "after": None}

    after, anchor = instrumenter(before)
    if after is None:
        payload["status"] = "anchor_missing"
        payload["instrumentation_error"] = f"instrumentation anchor not found: {anchor}"
        return {"probe": payload, "before": before, "after": None}

    payload["status"] = "instrumented"
    payload["instrumentation_error"] = None
    payload["instrumentation_anchor"] = anchor
    return {"probe": payload, "before": before, "after": after}


def _rocket_pmp_checker(text: str) -> tuple[str | None, str]:
    io_anchor = "val x = Output(Bool())"
    updated = _insert_after(
        text,
        io_anchor,
        [
            "    val access = Input(UInt(2.W))",
            "    val ptw = Input(Bool())",
            "    val valid = Input(Bool())",
        ],
    )
    if updated is None:
        return None, io_anchor
    anchor = "io.x := res.cfg.x"
    snippet = [
        "  when (io.valid) {",
        "    when (io.ptw) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check stage=ptw addr=0x%x prv=%d access=load allow=%d size=%d r=%d w=%d x=%d\\n",',
        "        io.addr, io.prv, io.r, io.size, io.r, io.w, io.x)",
        "    }.elsewhen (io.access === 2.U) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check stage=final addr=0x%x prv=%d access=fetch allow=%d size=%d r=%d w=%d x=%d\\n",',
        "        io.addr, io.prv, io.x, io.size, io.r, io.w, io.x)",
        "    }.elsewhen (io.access === 1.U) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check stage=final addr=0x%x prv=%d access=store allow=%d size=%d r=%d w=%d x=%d\\n",',
        "        io.addr, io.prv, io.w, io.size, io.r, io.w, io.x)",
        "    }.elsewhen (io.access === 0.U) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check stage=final addr=0x%x prv=%d access=load allow=%d size=%d r=%d w=%d x=%d\\n",',
        "        io.addr, io.prv, io.r, io.size, io.r, io.w, io.x)",
        "    }.otherwise {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check stage=final addr=0x%x prv=%d access=unknown allow=-1 size=%d r=%d w=%d x=%d\\n",',
        "        io.addr, io.prv, io.size, io.r, io.w, io.x)",
        "    }",
        "  }",
    ]
    return _insert_after(updated, anchor, snippet), anchor


def _rocket_ptw_access_exception(text: str) -> tuple[str | None, str]:
    anchor = "io.requestor(i).resp.bits.ae_final := resp_ae_final"
    snippet = [
        "    when (io.requestor(i).resp.valid) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception schema=3 chain=ptw-response stage=ptw level=%d ae_ptw=%d ae_final=%d authoritative=1 paddr=0x%x\\n",',
        "        max_count, resp_ae_ptw, resp_ae_final, pte_addr)",
        "    }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _rocket_tlb_exception_arbitration(text: str) -> tuple[str | None, str]:
    access_anchor = "val cmd_write = isWrite(io.req.bits.cmd)"
    updated = _insert_after(
        text,
        access_anchor,
        [
            "  val pmp_ptw = do_refill || io.req.bits.passthrough",
            "  val pmp_access = WireDefault(3.U(2.W))",
            "  when (pmp_ptw) {",
            "    pmp_access := 0.U",
            "  }.elsewhen (instruction.B) {",
            "    pmp_access := 2.U",
            "  }.elsewhen (cmd_write && !cmd_read) {",
            "    pmp_access := 1.U",
            "  }.elsewhen (cmd_read && !cmd_write) {",
            "    pmp_access := 0.U",
            "  }",
            "  pmp.io.access := pmp_access",
            "  pmp.io.ptw := pmp_ptw",
            "  pmp.io.valid := do_refill || io.req.fire",
        ],
    )
    if updated is None:
        return None, access_anchor
    anchor = "val pf_inst_array"
    snippet = [
        "  when (io.req.fire && vm_enabled) {",
        '    printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_exception_arbitration schema=2 chain=exception-arbitration stage=tlb vaddr=0x%x ptw_ae=0x%x ae_ld=0x%x ae_st=0x%x pf_ld=0x%x pf_st=0x%x pf_inst=0x%x\\n",',
        "      io.req.bits.vaddr, ptw_ae_array, ae_ld_array, ae_st_array, pf_ld_array, pf_st_array, pf_inst_array)",
        "  }",
    ]
    return _insert_after(updated, anchor, snippet), anchor


def _boom_lsu_tlb_pmp_check(text: str) -> tuple[str | None, str]:
    anchor = "val prot_x"
    snippet = [
        "  val pmp_ptw = widthMap(w => do_refill || io.req(w).bits.passthrough)",
        "  val pmp_access = widthMap(w => WireDefault(3.U(2.W)))",
        "  for (w <- 0 until memWidth) {",
        "    when (pmp_ptw(w)) {",
        "      pmp_access(w) := 0.U",
        "    }.elsewhen (isWrite(io.req(w).bits.cmd) && !isRead(io.req(w).bits.cmd)) {",
        "      pmp_access(w) := 1.U",
        "    }.elsewhen (isRead(io.req(w).bits.cmd) && !isWrite(io.req(w).bits.cmd)) {",
        "      pmp_access(w) := 0.U",
        "    }",
        "    pmp(w).io.access := pmp_access(w)",
        "    pmp(w).io.ptw := pmp_ptw(w)",
        "    pmp(w).io.valid := do_refill || io.req(w).fire",
        "    when (do_refill || io.req(w).fire) {",
        "      when (pmp_ptw(w)) {",
        '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check schema=2 role=diagnostic chain=pmp-check stage=ptw addr=0x%x prv=%d access=%d r=%d w=%d x=%d\\n",',
        "          mpu_physaddr(w), PRV.S.U, pmp_access(w), prot_r(w), prot_w(w), prot_x(w))",
        "      }.otherwise {",
        '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%x prv=%d access=%d r=%d w=%d x=%d\\n",',
        "          mpu_physaddr(w), priv, pmp_access(w), prot_r(w), prot_w(w), prot_x(w))",
        "      }",
        "    }",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_ptw_response_ae(text: str) -> tuple[str | None, str]:
    anchor = "newEntry.fragmented_superpage := io.ptw.resp.bits.fragmented_superpage"
    snippet = [
        '    printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae schema=3 role=diagnostic evidence=non_authoritative chain=ptw-response stage=ptw level=%d ae_ptw=%d ae_final=%d pte_page_base=0x%x\\n",',
        "      io.ptw.resp.bits.level, io.ptw.resp.bits.ae_ptw, io.ptw.resp.bits.ae_final, Cat(io.ptw.resp.bits.pte.ppn, 0.U(pgIdxBits.W)))",
    ]
    updated = _insert_after(text, anchor, snippet)
    if updated is not None:
        return updated, anchor
    fallback_anchor = "newEntry.ae := io.ptw.resp.bits.ae_final"
    return _insert_after(text, fallback_anchor, snippet), fallback_anchor


def _boom_ptw_ae_array(text: str) -> tuple[str | None, str]:
    anchor = "val pf_inst_array"
    snippet = [
        "  for (w <- 0 until memWidth) {",
        "    when (io.req(w).fire && vm_enabled(w)) {",
        '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array schema=2 role=diagnostic chain=exception-arbitration stage=tlb vaddr=0x%x ptw_ae=0x%x pf_ld=0x%x pf_st=0x%x pf_inst=0x%x\\n",',
        "        io.req(w).bits.vaddr, ptw_ae_array(w), pf_ld_array(w), pf_st_array(w), pf_inst_array(w))",
        "    }",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_ptw_request(text: str) -> tuple[str | None, str]:
    anchor = "io.ptw.req.bits.bits.addr := r_refill_tag"
    snippet = [
        "  when (io.ptw.req.fire) {",
        '    printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_request schema=3 role=diagnostic evidence=non_authoritative chain=ptw-request stage=ptw refill_tag=0x%x valid=%d\\n",',
        "      r_refill_tag, io.ptw.req.bits.valid)",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_target_operation_runtime(text: str) -> tuple[str | None, str]:
    updated = text
    if "val ldq_idx = dis_uops(w).bits.ldq_idx" in text:
        issue_anchor = "val ldq_idx = dis_uops(w).bits.ldq_idx"
        issue_updated = _insert_after(
            text,
            issue_anchor,
            [
                '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue pc=0x%x access=load ldq_idx=%d\n",',
                "        dis_uops(w).bits.debug_pc, ldq_idx)",
            ],
        )
        if issue_updated is not None:
            issue_anchor = "val stq_idx = dis_uops(w).bits.stq_idx"
            issue_updated = _insert_after(
                issue_updated,
                issue_anchor,
                [
                    '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue pc=0x%x access=store stq_idx=%d\n",',
                    "        dis_uops(w).bits.debug_pc, stq_idx)",
                ],
            )
            if issue_updated is not None:
                updated = issue_updated
    else:
        issue_anchor = 'assert (ld_enq_idx === io.core.dis_uops(w).bits.ldq_idx, "[lsu] mismatch enq load tag.")'
        issue_updated = _insert_after(
            text,
            issue_anchor,
            [
                '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue pc=0x%x access=load ldq_idx=%d\n",',
                "        io.core.dis_uops(w).bits.debug_pc, ld_enq_idx)",
            ],
        )
        if issue_updated is not None:
            issue_anchor = 'assert (st_enq_idx === io.core.dis_uops(w).bits.stq_idx, "[lsu] mismatch enq store tag.")'
            issue_updated = _insert_after(
                issue_updated,
                issue_anchor,
                [
                    '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue pc=0x%x access=store stq_idx=%d\n",',
                    "        io.core.dis_uops(w).bits.debug_pc, st_enq_idx)",
                ],
            )
            if issue_updated is not None:
                updated = issue_updated

    completion_guard_anchor = "if (MEMTRACE_PRINTF) {"
    if "val uop    = Mux(commit_store, s_uop, l_uop)" in updated:
        completion_snippet = [
            "    when (commit_store || commit_load) {",
            "      val pmpfuzz_runtime_uop = Mux(commit_store, s_uop, l_uop)",
            "      val pmpfuzz_runtime_addr = Mux(commit_store, stq_addr(temp_stq_commit_head).bits    , ldq_addr(temp_ldq_head).bits)",
            "      when (commit_store) {",
            '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed pc=0x%x addr=0x%x access=store size=%d stq_idx=%d\n",',
            "          pmpfuzz_runtime_uop.debug_pc, pmpfuzz_runtime_addr, (1.U << pmpfuzz_runtime_uop.mem_size), pmpfuzz_runtime_uop.stq_idx)",
            "      }.otherwise {",
            '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed pc=0x%x addr=0x%x access=load size=%d ldq_idx=%d\n",',
            "          pmpfuzz_runtime_uop.debug_pc, pmpfuzz_runtime_addr, (1.U << pmpfuzz_runtime_uop.mem_size), pmpfuzz_runtime_uop.ldq_idx)",
            "      }",
            "    }",
            "",
        ]
    else:
        completion_snippet = [
            "    when (commit_store || commit_load) {",
            "      val pmpfuzz_runtime_uop = Mux(commit_store, stq(idx).bits.uop, ldq(idx).bits.uop)",
            "      val pmpfuzz_runtime_addr = Mux(commit_store, stq(idx).bits.addr.bits, ldq(idx).bits.addr.bits)",
            "      when (commit_store) {",
            '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed pc=0x%x addr=0x%x access=store size=%d stq_idx=%d\n",',
            "          pmpfuzz_runtime_uop.debug_pc, pmpfuzz_runtime_addr, (1.U << pmpfuzz_runtime_uop.mem_size), pmpfuzz_runtime_uop.stq_idx)",
            "      }.otherwise {",
            '        printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed pc=0x%x addr=0x%x access=load size=%d ldq_idx=%d\n",',
            "          pmpfuzz_runtime_uop.debug_pc, pmpfuzz_runtime_addr, (1.U << pmpfuzz_runtime_uop.mem_size), pmpfuzz_runtime_uop.ldq_idx)",
            "      }",
            "    }",
            "",
        ]
    updated = _insert_before_next(
        updated,
        completion_guard_anchor,
        completion_guard_anchor,
        completion_snippet,
    )
    if updated is None:
        return None, completion_guard_anchor
    paddr_anchor = "val exe_tlb_uncacheable = widthMap(w => !(dtlb.io.resp(w).cacheable))"
    updated = _insert_after(
        updated,
        paddr_anchor,
        ["  val mem_xcpt_paddrs = RegNext(exe_tlb_paddr)"],
    )
    if updated is None:
        return None, paddr_anchor
    trap_anchor = "assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)"
    trap_snippet = [
        "      when (mem_xcpt_valids(w)) {",
        "        when (mem_xcpt_uops(w).uses_ldq) {",
        '          printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=trap pc=0x%x addr=0x%x access=load size=%d ldq_idx=%d mcause=%d mtval=0x%x\n",',
        "            mem_xcpt_uops(w).debug_pc, mem_xcpt_paddrs(w), (1.U << mem_xcpt_uops(w).mem_size), mem_xcpt_uops(w).ldq_idx, mem_xcpt_causes(w), mem_xcpt_vaddrs(w))",
        "        }.otherwise {",
        '          printf("PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=trap pc=0x%x addr=0x%x access=store size=%d stq_idx=%d mcause=%d mtval=0x%x\n",',
        "            mem_xcpt_uops(w).debug_pc, mem_xcpt_paddrs(w), (1.U << mem_xcpt_uops(w).mem_size), mem_xcpt_uops(w).stq_idx, mem_xcpt_causes(w), mem_xcpt_vaddrs(w))",
        "        }",
        "      }",
    ]
    return _insert_after(updated, trap_anchor, trap_snippet), trap_anchor


def _cva6_pmp_csr_state(text: str) -> tuple[str | None, str]:
    anchor = "assign pmpaddr_o = pmpaddr_q;"
    snippet = [
        "  integer pmpcfg_probe_entry_i;",
        "  logic [15:0] pmpcfg_probe_seen_q;",
        "  riscv::pmpcfg_t [15:0] pmpcfg_probe_prev_q;",
        "  logic [15:0][riscv::PLEN-3:0] pmpaddr_probe_prev_q;",
        "  always_ff @(posedge clk_i) begin",
        "    if (!rst_ni) begin",
        "      pmpcfg_probe_seen_q <= '0;",
        "      pmpcfg_probe_prev_q <= '{default: '0};",
        "      pmpaddr_probe_prev_q <= '{default: '0};",
        "    end else begin",
        "      for (pmpcfg_probe_entry_i = 0; pmpcfg_probe_entry_i < $size(pmpcfg_q); pmpcfg_probe_entry_i++) begin",
        "        if (!pmpcfg_probe_seen_q[pmpcfg_probe_entry_i]",
        "            || pmpcfg_probe_prev_q[pmpcfg_probe_entry_i] !== pmpcfg_q[pmpcfg_probe_entry_i]",
        "            || pmpaddr_probe_prev_q[pmpcfg_probe_entry_i] !== pmpaddr_q[pmpcfg_probe_entry_i]) begin",
        '          $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_pmp_csr_state chain=pmp-csr stage=csr entry=%0d cfg=0x%0h addr=0x%0h", pmpcfg_probe_entry_i, pmpcfg_q[pmpcfg_probe_entry_i], pmpaddr_q[pmpcfg_probe_entry_i]);',
        "          pmpcfg_probe_seen_q[pmpcfg_probe_entry_i] <= 1'b1;",
        "          pmpcfg_probe_prev_q[pmpcfg_probe_entry_i] <= pmpcfg_q[pmpcfg_probe_entry_i];",
        "          pmpaddr_probe_prev_q[pmpcfg_probe_entry_i] <= pmpaddr_q[pmpcfg_probe_entry_i];",
        "        end",
        "      end",
        "    end",
        "  end",
        "",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _cva6_ptw_pmp_check(text: str) -> tuple[str | None, str]:
    anchor = "if (data_rvalid_q) begin"
    snippet = [
        '            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_pmp_check schema=2 role=diagnostic chain=pmp-check stage=ptw addr=0x%0h prv=%0d access=load allow=%0d size=%0d", ptw_pptr_q, riscv::PRIV_LVL_S, allow_access, 8);',
    ]
    return _insert_after(text, anchor, snippet), anchor


def _cva6_mmu_pmp_check(text: str) -> tuple[str | None, str]:
    anchor = "module mmu"
    snippet = [
        "    logic mmu_fetch_probe_seen_q;",
        "    logic [riscv::PLEN-1:0] mmu_fetch_probe_addr_q;",
        "    riscv::priv_lvl_t mmu_fetch_probe_prv_q;",
        "    logic mmu_fetch_probe_allow_q;",
        "    logic mmu_data_probe_seen_q;",
        "    logic [riscv::PLEN-1:0] mmu_data_probe_addr_q;",
        "    riscv::priv_lvl_t mmu_data_probe_prv_q;",
        "    logic mmu_data_probe_store_q;",
        "    logic mmu_data_probe_allow_q;",
        "    always_ff @(posedge clk_i or negedge rst_ni) begin",
        "        if (!rst_ni) begin",
        "            mmu_fetch_probe_seen_q <= 1'b0;",
        "            mmu_fetch_probe_addr_q <= '0;",
        "            mmu_fetch_probe_prv_q <= riscv::PRIV_LVL_M;",
        "            mmu_fetch_probe_allow_q <= 1'b0;",
        "            mmu_data_probe_seen_q <= 1'b0;",
        "            mmu_data_probe_addr_q <= '0;",
        "            mmu_data_probe_prv_q <= riscv::PRIV_LVL_M;",
        "            mmu_data_probe_store_q <= 1'b0;",
        "            mmu_data_probe_allow_q <= 1'b0;",
        "        end else begin",
        "            if ((!enable_translation_i && icache_areq_i.fetch_req)",
        "                || (enable_translation_i && itlb_lu_hit && icache_areq_i.fetch_req && !iaccess_err)) begin",
        "                if (!mmu_fetch_probe_seen_q",
        "                    || mmu_fetch_probe_addr_q != icache_areq_o.fetch_paddr",
        "                    || mmu_fetch_probe_prv_q != priv_lvl_i",
        "                    || mmu_fetch_probe_allow_q != (match_any_execute_region && pmp_instr_allow)) begin",
        '                    $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=fetch allow=%0d", icache_areq_o.fetch_paddr, priv_lvl_i, match_any_execute_region && pmp_instr_allow);',
        "                end",
        "                mmu_fetch_probe_seen_q <= 1'b1;",
        "                mmu_fetch_probe_addr_q <= icache_areq_o.fetch_paddr;",
        "                mmu_fetch_probe_prv_q <= priv_lvl_i;",
        "                mmu_fetch_probe_allow_q <= match_any_execute_region && pmp_instr_allow;",
        "            end else begin",
        "                mmu_fetch_probe_seen_q <= 1'b0;",
        "            end",
        "",
        "            if (!misaligned_ex_q.valid) begin",
        "                if (!en_ld_st_translation_i && lsu_req_q) begin",
        "                    if (!mmu_data_probe_seen_q",
        "                        || mmu_data_probe_addr_q != lsu_paddr_o",
        "                        || mmu_data_probe_prv_q != ld_st_priv_lvl_i",
        "                        || mmu_data_probe_store_q != lsu_is_store_q",
        "                        || mmu_data_probe_allow_q != pmp_data_allow) begin",
        "                        if (lsu_is_store_q) begin",
        '                            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=store allow=%0d", lsu_paddr_o, ld_st_priv_lvl_i, pmp_data_allow);',
        "                        end else begin",
        '                            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=load allow=%0d", lsu_paddr_o, ld_st_priv_lvl_i, pmp_data_allow);',
        "                        end",
        "                    end",
        "                    mmu_data_probe_seen_q <= 1'b1;",
        "                    mmu_data_probe_addr_q <= lsu_paddr_o;",
        "                    mmu_data_probe_prv_q <= ld_st_priv_lvl_i;",
        "                    mmu_data_probe_store_q <= lsu_is_store_q;",
        "                    mmu_data_probe_allow_q <= pmp_data_allow;",
        "                end else if (en_ld_st_translation_i && dtlb_hit_q && lsu_req_q) begin",
        "                    if ((lsu_is_store_q && dtlb_pte_q.w && !daccess_err && dtlb_pte_q.d)",
        "                        || (!lsu_is_store_q && !daccess_err)) begin",
        "                        if (!mmu_data_probe_seen_q",
        "                            || mmu_data_probe_addr_q != lsu_paddr_o",
        "                            || mmu_data_probe_prv_q != ld_st_priv_lvl_i",
        "                            || mmu_data_probe_store_q != lsu_is_store_q",
        "                            || mmu_data_probe_allow_q != pmp_data_allow) begin",
        "                            if (lsu_is_store_q) begin",
        '                                $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=store allow=%0d", lsu_paddr_o, ld_st_priv_lvl_i, pmp_data_allow);',
        "                            end else begin",
        '                                $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=load allow=%0d", lsu_paddr_o, ld_st_priv_lvl_i, pmp_data_allow);',
        "                            end",
        "                        end",
        "                        mmu_data_probe_seen_q <= 1'b1;",
        "                        mmu_data_probe_addr_q <= lsu_paddr_o;",
        "                        mmu_data_probe_prv_q <= ld_st_priv_lvl_i;",
        "                        mmu_data_probe_store_q <= lsu_is_store_q;",
        "                        mmu_data_probe_allow_q <= pmp_data_allow;",
        "                    end else begin",
        "                        mmu_data_probe_seen_q <= 1'b0;",
        "                    end",
        "                end else begin",
        "                    mmu_data_probe_seen_q <= 1'b0;",
        "                end",
        "            end else begin",
        "                mmu_data_probe_seen_q <= 1'b0;",
        "            end",
        "        end",
        "    end",
        "",
    ]
    return _insert_before_next(text, anchor, "endmodule", snippet), f"{anchor} ... endmodule"


def _cva6_ptw_exception(text: str) -> tuple[str | None, str]:
    anchor = "assign bad_paddr_o = ptw_access_exception_o"
    snippet = [
        "    always_ff @(posedge clk_i) begin",
        "        if (rst_ni && ptw_access_exception_o) begin",
        '            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception schema=2 role=diagnostic chain=ptw-response stage=ptw level=%0d vaddr=0x%0h paddr=0x%0h allow=%0d exception=%0d", ptw_lvl_q, vaddr_q, ptw_pptr_q, allow_access, ptw_access_exception_o);',
        "        end",
        "    end",
        "",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _cva6_tlb_exception_arbitration(text: str) -> tuple[str | None, str]:
    anchor = "module tlb"
    snippet = [
        "    always_ff @(posedge clk_i) begin",
        "        if (rst_ni && (lu_access_i || flush_i || update_i.valid)) begin",
        '            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration schema=2 role=diagnostic chain=exception-arbitration stage=tlb vaddr=0x%0h hit=%0d flush=%0d update=%0d", lu_vaddr_i, lu_hit_o, flush_i, update_i.valid);',
        "        end",
        "    end",
        "",
    ]
    return _insert_before_next(text, anchor, "endmodule", snippet), f"{anchor} ... endmodule"


def _cva6_target_operation_issue(text: str) -> tuple[str | None, str]:
    anchor = "perf_counters i_perf_counters ("
    snippet = [
        "  always_ff @(posedge clk_i) begin",
        "    if (rst_ni) begin",
        "      if (lsu_valid_id_ex && fu_data_id_ex.fu == LOAD) begin",
        '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue access=load trans_id=%0d pc=0x%0h", fu_data_id_ex.trans_id, pc_id_ex);',
        "      end",
        "      if (lsu_valid_id_ex && fu_data_id_ex.fu == STORE) begin",
        '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue access=store trans_id=%0d pc=0x%0h", fu_data_id_ex.trans_id, pc_id_ex);',
        "      end",
        "    end",
        "  end",
        "",
    ]
    return _insert_before_next(text, anchor, "controller controller_i", snippet), f"{anchor} ... controller controller_i"


def _cva6_target_operation_runtime(text: str) -> tuple[str | None, str]:
    anchor = "always_comb begin : which_op"
    snippet = [
        "    logic [riscv::PLEN-1:0] pmpfuzz_load_paddr;",
        "    logic [riscv::PLEN-1:0] pmpfuzz_store_paddr;",
        "    logic [riscv::PLEN-1:0] pmpfuzz_load_paddr_o;",
        "    logic [riscv::PLEN-1:0] pmpfuzz_store_paddr_o;",
        "    assign pmpfuzz_load_paddr = ld_valid ? mmu_paddr : '0;",
        "    assign pmpfuzz_store_paddr = st_valid ? mmu_paddr : '0;",
        "    shift_reg #(",
        "        .dtype ( logic[$bits(pmpfuzz_load_paddr) - 1:0]),",
        "        .Depth ( NR_LOAD_PIPE_REGS )",
        "    ) i_pmpfuzz_pipe_reg_load_paddr (",
        "        .clk_i,",
        "        .rst_ni,",
        "        .d_i ( pmpfuzz_load_paddr ),",
        "        .d_o ( pmpfuzz_load_paddr_o )",
        "    );",
        "",
        "    shift_reg #(",
        "        .dtype ( logic[$bits(pmpfuzz_store_paddr) - 1:0]),",
        "        .Depth ( NR_STORE_PIPE_REGS )",
        "    ) i_pmpfuzz_pipe_reg_store_paddr (",
        "        .clk_i,",
        "        .rst_ni,",
        "        .d_i ( pmpfuzz_store_paddr ),",
        "        .d_o ( pmpfuzz_store_paddr_o )",
        "    );",
        "",
        "    always_ff @(posedge clk_i) begin",
        "        if (rst_ni) begin",
        "            if (load_valid_o) begin",
        "                if (load_exception_o.valid) begin",
        '                    $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=trap access=load trans_id=%0d addr=0x%0h mcause=%0d mtval=0x%0h", load_trans_id_o, pmpfuzz_load_paddr_o, load_exception_o.cause, load_exception_o.tval);',
        "                end else begin",
        '                    $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed access=load trans_id=%0d addr=0x%0h", load_trans_id_o, pmpfuzz_load_paddr_o);',
        "                end",
        "            end",
        "            if (store_valid_o) begin",
        "                if (store_exception_o.valid) begin",
        '                    $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=trap access=store trans_id=%0d addr=0x%0h mcause=%0d mtval=0x%0h", store_trans_id_o, pmpfuzz_store_paddr_o, store_exception_o.cause, store_exception_o.tval);',
        "                end else begin",
        '                    $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed access=store trans_id=%0d addr=0x%0h", store_trans_id_o, pmpfuzz_store_paddr_o);',
        "                end",
        "            end",
        "        end",
        "    end",
        "",
    ]
    return _insert_before_next(text, anchor, "endmodule", snippet), f"{anchor} ... endmodule"


_PROBE_INSTRUMENTERS = {
    "rocket_pmp_checker": _rocket_pmp_checker,
    "rocket_ptw_access_exception": _rocket_ptw_access_exception,
    "rocket_tlb_exception_arbitration": _rocket_tlb_exception_arbitration,
    "boom_lsu_tlb_pmp_check": _boom_lsu_tlb_pmp_check,
    "boom_ptw_response_ae": _boom_ptw_response_ae,
    "boom_ptw_ae_array": _boom_ptw_ae_array,
    "boom_ptw_request": _boom_ptw_request,
    "boom_target_operation_runtime": _boom_target_operation_runtime,
    "cva6_pmp_csr_state": _cva6_pmp_csr_state,
    "cva6_ptw_pmp_check": _cva6_ptw_pmp_check,
    "cva6_mmu_pmp_check": _cva6_mmu_pmp_check,
    "cva6_ptw_exception": _cva6_ptw_exception,
    "cva6_tlb_exception_arbitration": _cva6_tlb_exception_arbitration,
    "cva6_target_operation_issue": _cva6_target_operation_issue,
    "cva6_target_operation_runtime": _cva6_target_operation_runtime,
}


def _insert_after(text: str, anchor: str, snippet: list[str]) -> str | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if anchor in line:
            return _join_like(text, lines[: index + 1] + snippet + lines[index + 1 :])
    return None


def _insert_before_next(text: str, anchor: str, next_anchor: str, snippet: list[str]) -> str | None:
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines) if anchor in line), None)
    if start is None:
        return None
    for index in range(start, len(lines)):
        if next_anchor in lines[index]:
            return _join_like(text, lines[:index] + snippet + lines[index:])
    return None


def _join_like(original: str, lines: list[str]) -> str:
    text = "\n".join(lines)
    return text + ("\n" if original.endswith("\n") else "")


def _unified_diff(relative_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
        )
    )


def _safe_patch_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in name)
    return safe or "source-probes"


def _write_apply_script(out_dir: Path, patches: list[dict[str, Any]]) -> None:
    lines = ["#!/usr/bin/env sh", "set -eu", ""]
    for patch in patches:
        root = shlex.quote(str(patch["root"]))
        patch_path = shlex.quote(str((out_dir / str(patch["patch_file"])).resolve()))
        lines.extend(
            [
                f"(cd {root} && git apply --check {patch_path})",
                f"(cd {root} && git apply {patch_path})",
                "",
            ]
        )
    script = out_dir / "apply_source_probe_patches.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("\n".join(lines), encoding="ascii")
