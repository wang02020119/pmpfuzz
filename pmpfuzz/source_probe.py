from __future__ import annotations

from dataclasses import asdict, dataclass
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
                'chain=pmp-check stage=%s addr=0x%x allow=%d match=%d\\n", ...)'
            ),
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
                'chain=ptw-response stage=ptw level=%s ae_final=%d\\n", ...)'
            ),
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
                'chain=exception-arbitration stage=%s cause=%d ptw_ae=%d\\n", ...)'
            ),
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
                'chain=ptw-request stage=ptw paddr=0x%x refill=%d\\n", ...)'
            ),
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
                'chain=pmp-check stage=%s addr=0x%x allow=%d match=%d\\n", ...)'
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
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.sv",
            ),
            patterns=("pmpcfg_o", "pmpaddr_o", "pmpcfg_q", "pmpaddr_q"),
            signal_keys=("entry", "cfg", "addr", "locked"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_pmp_csr_state '
                'chain=pmp-csr entry=%d cfg=0x%x addr=0x%x\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_ptw_exception",
            dut="cva6-clean",
            security_chain="ptw-response",
            purpose="Observe CVA6 PTW/TLB access exceptions that decide page-walk PMP outcomes.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
            ),
            patterns=("ptw", "access_exception", "exception_o", "flush_tlb_o"),
            signal_keys=("stage", "level", "cause", "addr", "exception"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception '
                'chain=ptw-response stage=ptw level=%s cause=%d paddr=0x%x\\n", ...)'
            ),
        ),
        SourceProbeSpec(
            probe_id="cva6_tlb_exception_arbitration",
            dut="cva6-clean",
            security_chain="exception-arbitration",
            purpose="Observe CVA6 TLB exception priority around page/access faults and sfence flushes.",
            path_candidates=(
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
            ),
            patterns=("tlb", "exception", "flush_tlb", "access_exception"),
            signal_keys=("stage", "cause", "pf", "af", "flush"),
            instrumentation_hint=(
                'printf("PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration '
                'chain=exception-arbitration stage=%s cause=%d af=%d pf=%d\\n", ...)'
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
    selected = [spec for spec in (specs or default_source_probe_specs()) if spec.dut in requested]
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
