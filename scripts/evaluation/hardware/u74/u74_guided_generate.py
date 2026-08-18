#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from random import Random
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege
from pmpfuzz.scenario import TARGET_BASE, AccessProbe, PmpScenario
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec

import u74_formal_round0_prepare as frp
import u74_cl144_common as C

_ACCESS_VALUES = {a.value for a in Access}
_PRIV_BY_VALUE = {p.value.lower(): p for p in Privilege}
_PRIV_VALUES = set(_PRIV_BY_VALUE)
_MODES = {"na4", "napot", "tor"}
_RWX_BITS = ("read", "write", "execute")



def parse_bin(bin_id: str) -> dict[str, str]:
    parts = dict(part.split("=", 1) for part in str(bin_id).split("|"))
    return parts



def _entry_rwx(entry: PmpEntry) -> str:
    return f"{int(entry.read)}{int(entry.write)}{int(entry.execute)}"


def _build_scenario(
    *,
    non_harness: list[PmpEntry],
    privilege: Privilege,
    access: Access,
    address: int,
    size: int = 4,
    mprv: bool = False,
    mpp: Privilege = Privilege.M,
    match_mode: str = "na4",
    sv39: Any = None,
    virtual_address: int | None = None,
) -> PmpScenario:
    entries = list(non_harness) + frp._harness_entries_for_privilege(privilege)
    entries.sort(key=lambda e: e.index)
    probe = AccessProbe(access=access, physical_address=address, size=size,
                        offset_name="inside", virtual_address=virtual_address)
    return PmpScenario(
        name="gen",
        entries=entries,
        privilege=privilege,
        probe=probe,
        mprv=mprv,
        mpp=mpp,
        mseccfg=Mseccfg(),
        translation=TranslationMode.SV39 if sv39 is not None else TranslationMode.BARE,
        sv39=sv39,
        profile="legacy-data",
        sum_enabled=False,
        mxr=False,
        sfence_vma=True,
        coverage_tags=("closedloop-generated",),
        pmp_match_mode=match_mode,
        pte_permissions={},
        security_focus="u74-cl144-guided-gen",
        smepmp_rule=None,
        stateful_sequence=None,
    )


def _config_class_entries(mode: str, rwx: str, locked: bool, base: int) -> list[PmpEntry]:
    read, write, execute = bool(int(rwx[0])), bool(int(rwx[1])), bool(int(rwx[2]))
    if mode == "na4":
        return [
            PmpEntry(index=0, address_mode=AddressMode.NA4, pmpaddr=base >> 2,
                     read=read, write=write, execute=execute, locked=locked)
        ]
    if mode == "napot":
        return [
            PmpEntry(index=0, address_mode=AddressMode.NAPOT,
                     pmpaddr=PmpEntry.encode_napot(base=base, size=0x1000),
                     read=read, write=write, execute=execute, locked=locked)
        ]
    if mode == "tor":

        prev = PmpEntry(index=0, address_mode=AddressMode.NA4, pmpaddr=base >> 2,
                        read=False, write=False, execute=False, locked=False)
        tor = PmpEntry(index=1, address_mode=AddressMode.TOR, pmpaddr=(base + 0x1000) >> 2,
                       read=read, write=write, execute=execute, locked=locked)
        return [prev, tor]
    raise ValueError(f"unsupported config mode {mode}")


def _outcome_allows(access: Access, rwx: str) -> bool:
    return bool(int(rwx[{"load": 0, "store": 1, "fetch": 2}[access.value]]))


def _probe_address(mode: str, base: int) -> int:
    if mode == "na4":
        return base
    return base + 0x100


def _deny_rwx(access: str) -> str:
    return {"load": "010", "store": "100", "fetch": "110"}[access]



def construct_config(bin_id: str, *, base: int) -> PmpScenario | None:
    f = parse_bin(bin_id)
    mode = f.get("pmp_mode")
    rwx = f.get("permission_rwx")
    locked = f.get("locked") == "true"
    if mode not in _MODES or rwx not in {"000", "001", "010", "011", "100", "101", "110", "111"}:
        return None
    access = Access.LOAD if int(rwx[0]) or not any(int(b) for b in rwx) else Access.STORE
    entries = _config_class_entries(mode, rwx, locked, base)
    probe_address = _probe_address(mode, base)
    return _build_scenario(
        non_harness=entries, privilege=Privilege.U, access=access,
        address=probe_address, match_mode=mode,
    )


def construct_stimulus(bin_id: str, *, base: int) -> PmpScenario | None:
    f = parse_bin(bin_id)
    priv = f.get("privilege")
    eff = f.get("effective_privilege")
    acc = f.get("access")
    trans = f.get("translation")
    if priv not in _PRIV_VALUES or eff not in _PRIV_VALUES or acc not in _ACCESS_VALUES:
        return None
    if trans == "sv39" and acc == "fetch":
        return None
    privilege = _PRIV_BY_VALUE[priv]
    effective = _PRIV_BY_VALUE[eff]
    access = Access(acc)
    mprv = bool(privilege == Privilege.M and effective != Privilege.M)
    mpp = effective if mprv else Privilege.M
    rwx = "100" if acc == "load" else ("110" if acc == "store" else "101")
    entries = _config_class_entries("napot", rwx, False, base)
    sv39 = None
    virtual_address = None
    probe_addr = base + 0x100
    if trans == "sv39":
        sv39 = _make_sv39_mapping(base)
        virtual_address = sv39.virtual_page + 0x100
    return _build_scenario(
        non_harness=entries, privilege=privilege, access=access,
        address=probe_addr, mprv=mprv, mpp=mpp, match_mode="napot",
        sv39=sv39, virtual_address=virtual_address,
    )


def construct_privdec(bin_id: str, *, base: int) -> PmpScenario | None:
    f = parse_bin(bin_id)
    eff = f.get("effective_privilege")
    acc = f.get("access")
    deny = f.get("allow_or_deny") == "deny"
    if eff not in _PRIV_VALUES or acc not in _ACCESS_VALUES:
        return None
    access = Access(acc)
    effective = _PRIV_BY_VALUE[eff]
    rwx = _deny_rwx(acc) if deny else ("100" if acc == "load" else ("110" if acc == "store" else "101"))


    locked = bool(deny and effective == Privilege.M)
    entries = _config_class_entries("napot", rwx, locked, base)
    return _build_scenario(
        non_harness=entries, privilege=effective, access=access,
        address=_probe_address("napot", base), match_mode="napot",
    )


def construct_modedec(bin_id: str, *, base: int) -> PmpScenario | None:
    f = parse_bin(bin_id)
    mode = f.get("pmp_mode")
    acc = f.get("access")
    deny = f.get("allow_or_deny") == "deny"
    if mode not in _MODES and mode != "off":
        return None
    if acc not in _ACCESS_VALUES:
        return None
    access = Access(acc)
    if mode == "off":

        rwx = "000"
        entries = _config_class_entries("napot", rwx, False, base + 0x4000)
        return _build_scenario(
            non_harness=entries, privilege=Privilege.U, access=access,
            address=base + 0x100, match_mode="napot",
        )
    rwx = _deny_rwx(acc) if deny else ("100" if acc == "load" else ("110" if acc == "store" else "101"))
    entries = _config_class_entries(mode, rwx, False, base)
    return _build_scenario(
        non_harness=entries, privilege=Privilege.U, access=access,
        address=_probe_address(mode, base), match_mode=mode,
    )


def construct_decision(bin_id: str, *, base: int) -> PmpScenario | None:
    f = parse_bin(bin_id)
    acc = f.get("access")
    cause = f.get("mcause_class")
    if acc not in _ACCESS_VALUES:
        return None
    if str(cause) == "other":
        return None
    access = Access(acc)
    deny = True
    rwx = _deny_rwx(acc.value)
    entries = _config_class_entries("napot", rwx, False, base)
    return _build_scenario(
        non_harness=entries, privilege=Privilege.U, access=access,
        address=base + 0x100, match_mode="napot",
    )


def _make_sv39_mapping(base: int):
    return Sv39Mapping(
        virtual_page=0x80000000,
        physical_page=base,
        root_table=base + 0x10000,
        page_size=0x1000,
        walk_addresses=(base + 0x10100, base + 0x10108, base + 0x10110),
        pte=PageTableEntry(read=True, write=True, execute=True, user=True, accessed=True, dirty=False, valid=True, global_mapping=False),
    )


_CONSTRUCTORS = {
    "family=config": construct_config,
    "family=stimulus": construct_stimulus,
    "family=privilege-decision": construct_privdec,
    "family=mode-decision": construct_modedec,
    "family=decision": construct_decision,
}



def _assemble(scenario: PmpScenario, *, seed: int, index: int, name: str, target: str, operator: str, parent_id: str) -> dict[str, Any] | None:
    if not frp._is_supported_formal_scenario(scenario):
        return None
    translation = "sv39" if scenario.sv39 is not None else "bare"
    access = str(scenario.probe.access.value)
    if translation == "sv39" and access == "fetch":
        return None
    if any(e.address_mode == AddressMode.TOR for e in frp._non_harness_entries(scenario)):



        return None
    try:
        case, lowering = C.build_case_and_lowering(scenario, seed=seed, index=index, case_name=name)
    except (ValueError, AssertionError):
        return None
    expected = case["expected"]
    predicted = C.predict_case_bins(
        case, expected_allowed=bool(expected["allowed"]), expected_cause=expected["trap_cause"],
    )
    if not predicted.get("eligible"):
        return None
    reachable_set = set(_REACHABLE)
    predicted_bins = sorted(set(str(b) for b in (predicted.get("observed_bins") or [])))
    predicted_reachable = sorted(set(predicted_bins) & reachable_set)
    if target and target not in predicted_reachable:
        return None
    scenario_hash_value = scenario_hash(scenario_to_spec(scenario))
    if scenario_hash_value != case["scenario_hash"]:
        raise RuntimeError("hash drift after rename")
    return {
        "name": name,
        "candidate_id": C.make_candidate_id(seed=seed, profile=scenario.profile, generator_index=index,
                                            scenario_hash=scenario_hash_value, mutation=operator),
        "scenario_hash": scenario_hash_value,
        "scenario_fingerprint": scenario_hash_value,
        "profile": scenario.profile,
        "generator_profile": scenario.profile,
        "generator_index": index,
        "mutation_operator": operator,
        "seed": seed,
        "case_index": index,
        "operator": operator,
        "parent_case_id": parent_id,
        "target_bin": target,
        "config_classes": C.config_classes_for_scenario(scenario),
        "predicted_bins": predicted_bins,
        "predicted_reachable_bins": predicted_reachable,
        "scenario_spec": case["scenario_spec"],
        "lowering": lowering,
        "expected": expected,
        "firmware_ready": True,
        "board_unstable": False,
        "has_tor": any(e.address_mode.name.lower() == "tor" for e in frp._non_harness_entries(scenario)),
        "has_locked": any(bool(e.locked) for e in frp._non_harness_entries(scenario)),
        "translation": "sv39" if scenario.sv39 is not None else "bare",
        "access": scenario.probe.access.value,
    }



def generate_round(
    *,
    seed_pool: list[dict[str, Any]],
    universe: dict[str, Any],
    prior_summary: dict[str, Any] | None,
    round_index: int,
    budget: int,
    seed: int,
    executed_hashes: set[str],
    max_locked: int = 20,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    global _REACHABLE
    _REACHABLE = C.reachable_bins(universe)

    prior_covered = set(str(b) for b in (prior_summary or {}).get("cumulative_covered_bins") or [])
    reachable_set = set(_REACHABLE)
    missing = sorted(reachable_set - prior_covered)

    parents = [p for p in seed_pool if not p.get("board_unstable")]
    rng = Random((int(seed) + int(round_index) * 7919) & 0x7FFFFFFF)

    generated: list[dict[str, Any]] = []
    seen_hashes = set(executed_hashes)
    index = 0
    log: dict[str, Any] = {"missing_bins": missing, "targeted": [], "skipped_targets": [], "fill_ops": {}}
    locked_picked = 0

    def _try_add(scenario: PmpScenario | None, *, target: str, operator: str, parent_id: str) -> bool:
        nonlocal index, locked_picked
        if scenario is None:
            return False
        name = f"u74-cl144-r{round_index}-case-{index:04d}"
        cand = _assemble(scenario, seed=seed, index=index, name=name, target=target,
                         operator=operator, parent_id=parent_id)
        if cand is None:
            return False
        if cand["scenario_hash"] in seen_hashes:
            return False
        if cand.get("has_locked") and locked_picked >= max_locked:
            return False
        seen_hashes.add(cand["scenario_hash"])
        generated.append(cand)
        index += 1
        if cand.get("has_locked"):
            locked_picked += 1
        return True

    for target in missing:
        family = str(target).split("|", 1)[0]
        ctor = _CONSTRUCTORS.get(family)
        if ctor is None:
            log["skipped_targets"].append({"bin": target, "reason": "no-constructor"})
            continue
        if "|mcause_class=other" in target:
            log["skipped_targets"].append({"bin": target, "reason": "unexpected-trap-cause-not-directable"})
            continue
        base = TARGET_BASE + (index % 8) * frp.SOURCE_TARGET_STRIDE
        scenario = ctor(target, base=base)
        ok = _try_add(scenario, target=target, operator=f"construct:{family}", parent_id="")
        if ok:
            log["targeted"].append(target)
        else:
            log["skipped_targets"].append({"bin": target, "reason": "construction-failed-or-duplicate"})

    def _parent_weight(p: dict[str, Any]) -> int:
        pred = set(p.get("predicted_reachable_bins") or [])
        return len(pred & set(missing))

    ranked = sorted(parents, key=_parent_weight, reverse=True)
    fill_op_order = ("toggle-pmp-permissions", "toggle-access", "toggle-privilege", "toggle-mprv-mpp", "toggle-pmp-address-mode")
    while len(generated) < budget:
        progress = False
        for parent in ranked:
            if len(generated) >= budget:
                break
            spec = parent.get("scenario_spec")
            if not spec:
                continue
            try:
                parent_scenario = scenario_from_spec(spec)
            except Exception:
                continue
            for op in fill_op_order:
                if len(generated) >= budget:
                    break
                for attempt in range(4):
                    if len(generated) >= budget:
                        break
                    mutated = _fill_mutate(parent_scenario, op, attempt, seed=seed)
                    if mutated is None:
                        continue
                    ok = _try_add(mutated, target="", operator=f"fill:{op}", parent_id=str(parent.get("candidate_id") or parent.get("name") or ""))
                    if ok:
                        progress = True
                        log["fill_ops"][op] = log["fill_ops"].get(op, 0) + 1
                        break
        if not progress and len(generated) < budget:
            break

    stats = {
        "budget": budget,
        "generated_count": len(generated),
        "missing_count": len(missing),
        "targeted_bin_count": len(log["targeted"]),
        "skipped_target_count": len(log["skipped_targets"]),
        "fill_ops": log["fill_ops"],
    }
    return generated, {"stats": stats, "log": log}


def _fill_mutate(parent_scenario: PmpScenario, op: str, attempt: int, *, seed: int) -> PmpScenario | None:
    from pmpfuzz.continuous import ScenarioStream

    stream = ScenarioStream(root_seed=seed, include_experimental=False)
    try:
        spec = scenario_to_spec(parent_scenario)
        return stream.mutate(spec, op, attempt)
    except ValueError:
        return None



def emit_schedule(entries: list[dict[str, Any]], *, round_index: int, selection_source: str, seed: int, out_dir: Path, log: dict[str, Any], stats: dict[str, Any], corpus_hash: str, unsupported_bins: list[str]) -> None:
    from u74_guided_select import build_catalog_entries, build_schedule_entries

    schedule_entries = build_schedule_entries(
        [(c, {"marginal_gain": 0, "predicted_bins": c.get("predicted_bins") or [], "predicted_new_bins": [], "config_classes": c.get("config_classes") or []}) for c in entries],
        round_index=round_index, selection_source=selection_source,
    )
    for entry, cand in zip(schedule_entries, entries):
        entry["operator"] = cand.get("operator")
        entry["parent_case_id"] = cand.get("parent_case_id") or ""
        entry["target_bin"] = cand.get("target_bin") or ""
        entry["generation_seed"] = seed
    schedule = {
        "schema_version": 1,
        "round_id": f"round-{round_index:04d}",
        "campaign_id": C.CAMPAIGN_ID,
        "seed": seed,
        "selection_source": selection_source,
        "selection_summary": {
            "mode": "guided-generate",
            "budget": len(entries),
            "count": len(entries),
            "targeted_bin_count": stats.get("targeted_bin_count", 0),
        },
        "entries": schedule_entries,
    }
    C.write_json(out_dir / f"schedule_round_{round_index:04d}.json", schedule)
    C.write_json(out_dir / "catalog.json", {"schema_version": 1, "cases": build_catalog_entries(schedule_entries)})
    generation_log = {
        "schema_version": 1,
        "round_id": f"round-{round_index:04d}",
        "mode": "guided-generate",
        "seed": seed,
        "budget": len(entries),
        "selection_source": selection_source,
        "tie_break_rule": "deterministic generator seed; locked cases capped",
        "seed_pool_hash": corpus_hash,
        "seed_pool_path": str(out_dir.parent.parent / "aggregation" / "seed-pool.json"),
        "prior_covered_bins": sorted((log.get("prior_covered") or [])),
        "missing_bins": log.get("missing_bins") or [],
        "targeted_bins": log.get("targeted") or [],
        "skipped_targets": log.get("skipped_targets") or [],
        "fill_ops": log.get("fill_ops") or {},
        "generated": [
            {
                "name": c["name"],
                "candidate_id": c["candidate_id"],
                "scenario_hash": c["scenario_hash"],
                "operator": c.get("operator"),
                "parent_case_id": c.get("parent_case_id"),
                "target_bin": c.get("target_bin"),
                "predicted_bins": c.get("predicted_bins"),
            }
            for c in entries
        ],
        "unsupported_bins": unsupported_bins,
        "unsupported_bin_count": len(unsupported_bins),
    }
    C.write_json(out_dir / "generation-log.json", generation_log)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="U74 closedloop-144 coverage-guided generation")
    parser.add_argument("--seed-pool", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=96)
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--prior-summary", type=Path, required=True)
    parser.add_argument("--max-locked", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    seed_pool = C.load_json(args.seed_pool).get("candidates") or []
    prior = C.load_json(args.prior_summary) if Path(args.prior_summary).exists() else None
    executed_hashes = set(str(h) for h in ((prior or {}).get("executed_scenario_hashes") or []))

    generated, result = generate_round(
        seed_pool=seed_pool,
        universe=universe,
        prior_summary=prior,
        round_index=args.round_index,
        budget=args.budget,
        seed=args.seed,
        executed_hashes=executed_hashes,
        max_locked=args.max_locked,
    )
    if len(generated) < args.budget:
        raise SystemExit(
            f"generation produced only {len(generated)}/{args.budget} candidates "
            f"(missing {len(result['log']['missing_bins'])}, targeted {len(result['log']['targeted'])})"
        )
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    emit_schedule(
        generated, round_index=args.round_index,
        selection_source="u74-guided-generate-v1", seed=args.seed, out_dir=out,
        log={**result["log"], "prior_covered": list((prior or {}).get("cumulative_covered_bins") or [])},
        stats=result["stats"],
        corpus_hash=str(C.load_json(args.seed_pool).get("corpus_fingerprint") or ""),
        unsupported_bins=C.compute_unsupported_bins(universe),
    )
    s = result["stats"]
    print(f"guided-generate round-{args.round_index:04d}: generated {s['generated_count']}/{s['budget']} "
          f"(missing {s['missing_count']}, targeted {s['targeted_bin_count']}, skipped {s['skipped_target_count']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
