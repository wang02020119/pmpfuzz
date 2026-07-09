from __future__ import annotations

import difflib
import shlex
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
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("ptw", "access_exception", "exception_o", "ptw_access_exception_o"),
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
                "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
            ),
            patterns=("tlb", "exception", "flush_tlb", "access_exception", "flush_i", "lu_hit_o"),
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
    anchor = "io.x := res.cfg.x"
    snippet = [
        '  when (io.addr.orR) {',
        '    printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker chain=pmp-check stage=pmp addr=0x%x prv=%d size=%d r=%d w=%d x=%d\\n",',
        "      io.addr, io.prv, io.size, io.r, io.w, io.x)",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _rocket_ptw_access_exception(text: str) -> tuple[str | None, str]:
    anchor = "io.requestor(i).resp.bits.ae_final := resp_ae_final"
    snippet = [
        "    when (io.requestor(i).resp.valid) {",
        '      printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response stage=ptw level=%d ae_ptw=%d ae_final=%d paddr=0x%x\\n",',
        "        max_count, resp_ae_ptw, resp_ae_final, r_pte.ppn)",
        "    }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _rocket_tlb_exception_arbitration(text: str) -> tuple[str | None, str]:
    anchor = "val pf_inst_array"
    snippet = [
        "  when (io.req.valid && vm_enabled) {",
        '    printf("PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_exception_arbitration chain=exception-arbitration stage=tlb vaddr=0x%x ptw_ae=0x%x ae_ld=0x%x ae_st=0x%x pf_ld=0x%x pf_st=0x%x pf_inst=0x%x\\n",',
        "      io.req.bits.vaddr, ptw_ae_array, ae_ld_array, ae_st_array, pf_ld_array, pf_st_array, pf_inst_array)",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_lsu_tlb_pmp_check(text: str) -> tuple[str | None, str]:
    anchor = "val prot_x"
    snippet = [
        "  for (w <- 0 until memWidth) {",
        "    when (io.req(w).valid || do_refill) {",
        '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check chain=pmp-check stage=lsu addr=0x%x prv=%d r=%d w=%d x=%d\\n",',
        "        mpu_physaddr(w), Mux(usingVM.B && (do_refill || io.req(w).bits.passthrough), PRV.S.U, priv), prot_r(w), prot_w(w), prot_x(w))",
        "    }",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_ptw_response_ae(text: str) -> tuple[str | None, str]:
    anchor = "newEntry.fragmented_superpage := io.ptw.resp.bits.fragmented_superpage"
    snippet = [
        '    printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae chain=ptw-response stage=ptw level=%d ae_final=%d paddr=0x%x\\n",',
        "      io.ptw.resp.bits.level, io.ptw.resp.bits.ae_final, Cat(io.ptw.resp.bits.pte.ppn, 0.U(pgIdxBits.W)))",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_ptw_ae_array(text: str) -> tuple[str | None, str]:
    anchor = "val pf_inst_array"
    snippet = [
        "  for (w <- 0 until memWidth) {",
        "    when (io.req(w).valid && vm_enabled(w)) {",
        '      printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array chain=exception-arbitration stage=tlb vaddr=0x%x ptw_ae=0x%x pf_ld=0x%x pf_st=0x%x pf_inst=0x%x\\n",',
        "        io.req(w).bits.vaddr, ptw_ae_array(w), pf_ld_array(w), pf_st_array(w), pf_inst_array(w))",
        "    }",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _boom_ptw_request(text: str) -> tuple[str | None, str]:
    anchor = "io.ptw.req.bits.bits.addr := r_refill_tag"
    snippet = [
        "  when (io.ptw.req.valid) {",
        '    printf("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_request chain=ptw-request stage=ptw paddr=0x%x valid=%d\\n",',
        "      r_refill_tag, io.ptw.req.bits.valid)",
        "  }",
    ]
    return _insert_after(text, anchor, snippet), anchor


def _cva6_pmp_csr_state(text: str) -> tuple[str | None, str]:
    anchor = ".pmpaddr_o"
    snippet = [
        "  always_ff @(posedge clk_i) begin",
        "    if (rst_ni) begin",
        '      $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_pmp_csr_state chain=pmp-csr stage=csr cfg=0x%0h addr=0x%0h", pmpcfg, pmpaddr);',
        "    end",
        "  end",
        "",
    ]
    return _insert_before_next(text, anchor, "endmodule", snippet), f"{anchor} ... endmodule"


def _cva6_ptw_exception(text: str) -> tuple[str | None, str]:
    anchor = "assign bad_paddr_o = ptw_access_exception_o"
    snippet = [
        "    always_ff @(posedge clk_i) begin",
        "        if (rst_ni && ptw_access_exception_o) begin",
        '            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception chain=ptw-response stage=ptw paddr=0x%0h allow=%0d exception=%0d", ptw_pptr_q, allow_access, ptw_access_exception_o);',
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
        '            $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration chain=exception-arbitration stage=tlb vaddr=0x%0h hit=%0d flush=%0d update=%0d", lu_vaddr_i, lu_hit_o, flush_i, update_i.valid);',
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
    "cva6_pmp_csr_state": _cva6_pmp_csr_state,
    "cva6_ptw_exception": _cva6_ptw_exception,
    "cva6_tlb_exception_arbitration": _cva6_tlb_exception_arbitration,
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
