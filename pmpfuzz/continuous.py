from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, replace
from random import Random
from typing import Any, Iterable

from .pmp import PmpEntry, Privilege
from .scenario import (
    M_DATA_BASE,
    M_DATA_SIZE,
    M_TEXT_BASE,
    M_TEXT_SIZE,
    PAGE_TABLE_BASE,
    PAGE_TABLE_SIZE,
    SU_CODE_BASE,
    SU_CODE_SIZE,
    ScenarioGenerator,
)
from .scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from .semantic_coverage import CORE_STATEFUL_TARGET, PROFILE_TARGET_COUNTS, target_profiles


DEFAULT_MUTATION_OPERATORS = (
    "toggle-probe-address",
    "toggle-access",
    "toggle-access-size",
    "toggle-privilege",
    "toggle-mprv-mpp",
    "toggle-pmp-permissions",
    "toggle-pmp-address-mode",
    "pmp-entry-topology",
    "toggle-mseccfg",
    "toggle-pte-permissions",
    "toggle-sum-mxr-sfence",
    "toggle-stateful-sequence",
)

_RWX_CHOICES = ("---", "r--", "rw-", "r-x", "rwx")
_STATEFUL_MUTATIONS = ("none", "pmpcfg-deny-target", "pmpcfg-deny-ptw", "pte-deny-leaf")
_STATEFUL_FENCES = ("none", "with-sfence", "with-sfence-fence-i", "no-fence-experimental")
_EXPLICIT_OPERATOR_RE = re.compile(r"^(?P<name>[a-z0-9-]+)=(?P<value>.+)$")

_HARNESS_PMPADDRS = {
    PmpEntry.encode_napot(base=M_TEXT_BASE, size=M_TEXT_SIZE),
    PmpEntry.encode_napot(base=M_DATA_BASE, size=M_DATA_SIZE),
    PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
    PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE),
}


@dataclass(frozen=True)
class GeneratedRootScenario:
    scenario: object
    generation_seed: int
    scenario_index: int
    profile: str
    generator_variant: str
    root_sequence: int


class ScenarioStream:
    def __init__(
        self,
        *,
        root_seed: int,
        target: str = CORE_STATEFUL_TARGET,
        include_experimental: bool = False,
        profiles: Iterable[str] | None = None,
        generator_variant: str = "full",
    ) -> None:
        self.root_seed = int(root_seed)
        self.target = target
        self.include_experimental = include_experimental
        self.profiles = tuple(profiles) if profiles is not None else target_profiles(target, include_experimental)
        self.generator_variant = str(generator_variant)
        if not self.profiles:
            raise ValueError("ScenarioStream requires at least one profile")

    def generate_root(self, sequence: int):
        return self.generate_root_with_metadata(sequence).scenario

    def generate_root_with_metadata(self, sequence: int) -> GeneratedRootScenario:
        if sequence < 0:
            raise ValueError("sequence must be >= 0")
        seed = _derived_seed(self.root_seed, "root", sequence)
        rng = Random(seed)
        profile = self.profiles[rng.randrange(len(self.profiles))]
        index = rng.randrange(_profile_index_space(profile))
        generator = ScenarioGenerator(
            seed=seed,
            include_smepmp=profile.startswith("smepmp"),
            profile=profile,
            generator_variant=self.generator_variant,
        )
        scenario = generator.generate_one(index)
        return GeneratedRootScenario(
            scenario=replace(scenario, name=f"root_{sequence:08d}"),
            generation_seed=seed,
            scenario_index=index,
            profile=profile,
            generator_variant=self.generator_variant,
            root_sequence=sequence,
        )

    def applicable_operators(self, parent_spec: dict[str, Any]) -> tuple[str, ...]:
        spec = _validated_spec(parent_spec)
        operators: list[str] = [
            "toggle-probe-address",
            "toggle-access",
            "toggle-privilege",
            "toggle-mprv-mpp",
            "toggle-pmp-permissions",
            "toggle-pmp-address-mode",
            "toggle-mseccfg",
            "toggle-sum-mxr-sfence",
        ]
        if str(((spec.get("probe") or {}).get("access") or "")) != "fetch":
            operators.append("toggle-access-size")
        if _mutable_entry_positions(spec, require_two=True):
            operators.append("pmp-entry-topology")
        if spec.get("sv39") is not None or spec.get("pte_permissions"):
            operators.append("toggle-pte-permissions")
        if spec.get("stateful_sequence") is not None:
            operators.append("toggle-stateful-sequence")
        return tuple(operators)

    def mutate(self, parent_spec: dict[str, Any], operator: str, attempt: int):
        spec = _validated_spec(parent_spec)
        parent_hash = scenario_hash(spec)
        rng = Random(_derived_seed(self.root_seed, parent_hash, operator, attempt))
        mutated = copy.deepcopy(spec)

        explicit = _parse_explicit_operator(operator)
        if explicit is not None:
            name, value = explicit
            self._apply_explicit_operator(mutated, name, value, rng)
        else:
            self._apply_operator(mutated, operator, rng)

        mutated["name"] = _stable_mutation_name(operator, attempt)
        scenario = scenario_from_spec(mutated)
        normalized = scenario_to_spec(scenario)
        return scenario_from_spec(normalized)

    def mutation_generation_seed(self, parent_hash: str, operator: str, attempt: int) -> int:
        return _derived_seed(self.root_seed, parent_hash, operator, attempt)

    def _apply_operator(self, spec: dict[str, Any], operator: str, rng: Random) -> None:
        if operator == "toggle-probe-address":
            _mutate_probe_address(spec, rng)
            return
        if operator == "toggle-access":
            _mutate_access(spec, rng)
            return
        if operator == "toggle-access-size":
            _mutate_access_size(spec, rng)
            return
        if operator == "toggle-privilege":
            _mutate_privilege(spec, rng)
            return
        if operator == "toggle-mprv-mpp":
            _mutate_mprv_mpp(spec, rng)
            return
        if operator == "toggle-pmp-permissions":
            _mutate_pmp_permissions(spec, rng)
            return
        if operator == "toggle-pmp-address-mode":
            _mutate_pmp_address_mode(spec, rng)
            return
        if operator == "pmp-entry-topology":
            _mutate_pmp_entry_topology(spec, rng)
            return
        if operator == "toggle-mseccfg":
            _mutate_mseccfg(spec, rng)
            return
        if operator == "toggle-pte-permissions":
            _mutate_pte_permissions(spec, rng)
            return
        if operator == "toggle-sum-mxr-sfence":
            _mutate_sum_mxr_sfence(spec, rng)
            return
        if operator == "toggle-stateful-sequence":
            _mutate_stateful_sequence(spec, rng)
            return
        raise ValueError(f"unsupported mutation operator: {operator}")

    def _apply_explicit_operator(self, spec: dict[str, Any], name: str, value: str, rng: Random) -> None:
        if name == "set-access":
            _mutate_access(spec, rng, target=value)
            return
        if name == "set-privilege":
            _mutate_privilege(spec, rng, target=value)
            return
        if name == "set-mxr":
            _set_bool_field(spec, "mxr", _parse_bool_digit(value))
            return
        if name == "set-pmp-locked":
            _set_entry_locked(spec, _parse_bool_digit(value))
            return
        if name == "set-pte-rwx":
            _mutate_pte_permissions(spec, rng, target_rwx=value)
            return
        if name == "set-mseccfg-mml":
            _set_mseccfg_bit(spec, "mml", _parse_bool_digit(value))
            return
        if name == "set-mseccfg-mmwp":
            _set_mseccfg_bit(spec, "mmwp", _parse_bool_digit(value))
            return
        if name == "set-mseccfg-rlb":
            _set_mseccfg_bit(spec, "rlb", _parse_bool_digit(value))
            return
        if name == "set-stateful-mutation":
            _set_stateful_field(spec, "mutation", value, _STATEFUL_MUTATIONS)
            return
        if name == "set-fence":
            _set_stateful_field(spec, "fence", value, _STATEFUL_FENCES)
            return
        raise ValueError(f"unsupported explicit mutation operator: {name}={value}")


def _profile_index_space(profile: str) -> int:
    count = int(PROFILE_TARGET_COUNTS.get(profile) or 0)
    if count > 0:
        return count
    # Dedicated experiment profiles such as sv39-final-pmp are valid scenario
    # generators even when they are not part of the semantic target-count map.
    return 256


def _validated_spec(parent_spec: dict[str, Any]) -> dict[str, Any]:
    scenario = scenario_from_spec(parent_spec)
    return scenario_to_spec(scenario)


def _derived_seed(root_seed: int, *parts: object) -> int:
    digest = hashlib.sha256()
    digest.update(str(root_seed).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(str(part).encode("ascii"))
    return int.from_bytes(digest.digest()[:8], byteorder="big", signed=False)


def _parse_explicit_operator(operator: str) -> tuple[str, str] | None:
    match = _EXPLICIT_OPERATOR_RE.match(operator)
    if not match:
        return None
    return match.group("name"), match.group("value")


def _stable_mutation_name(operator: str, attempt: int) -> str:
    compact = re.sub(r"[^a-zA-Z0-9]+", "-", operator).strip("-").lower()
    return f"mut-{compact[:32]}-{attempt:04d}"


def _mutate_probe_address(spec: dict[str, Any], rng: Random) -> None:
    probe = _require_dict(spec, "probe")
    size = int(probe.get("size") or 4)
    step = 8 if size == 8 else 4
    physical = int(probe["physical_address"])
    page_base = physical & ~0xFFF
    current_offset = physical & 0xFFF
    candidate_offsets = [0, step, 0x100, 0x200, 0x3FC, 0x7F8 if step == 8 else 0x7FC, 0xFF8 if step == 8 else 0xFFC]
    candidate_offsets = [offset for offset in candidate_offsets if offset != current_offset and offset % step == 0]
    if not candidate_offsets:
        raise ValueError("no alternate probe offsets available")
    new_offset = candidate_offsets[rng.randrange(len(candidate_offsets))]
    probe["physical_address"] = page_base + new_offset
    if probe.get("virtual_address") is not None:
        virtual = int(probe["virtual_address"])
        probe["virtual_address"] = (virtual & ~0xFFF) + new_offset


def _mutate_access(spec: dict[str, Any], rng: Random, target: str | None = None) -> None:
    probe = _require_dict(spec, "probe")
    current = str(probe.get("access") or "")
    choices = ("load", "store", "fetch")
    if target is not None:
        if target not in choices:
            raise ValueError(f"unsupported access target: {target}")
        if target == current:
            raise ValueError("requested access already set")
        probe["access"] = target
    else:
        probe["access"] = _choose_other(rng, choices, current)
    if probe["access"] == "fetch":
        probe["size"] = 4


def _mutate_access_size(spec: dict[str, Any], rng: Random) -> None:
    probe = _require_dict(spec, "probe")
    if str(probe.get("access") or "") == "fetch":
        raise ValueError("fetch probes do not support access-size mutation")
    current = int(probe.get("size") or 4)
    if current not in {4, 8}:
        raise ValueError(f"unsupported probe size for mutation: {current}")
    probe["size"] = 8 if current == 4 else 4


def _mutate_privilege(spec: dict[str, Any], rng: Random, target: str | None = None) -> None:
    current = str(spec.get("privilege") or "")
    choices = tuple(item.value for item in Privilege)
    if target is not None:
        if target not in choices:
            raise ValueError(f"unsupported privilege target: {target}")
        if target == current:
            raise ValueError("requested privilege already set")
        spec["privilege"] = target
    else:
        spec["privilege"] = _choose_other(rng, choices, current)


def _mutate_mprv_mpp(spec: dict[str, Any], rng: Random) -> None:
    spec["mprv"] = not bool(spec.get("mprv"))
    spec["mpp"] = _choose_other(rng, tuple(item.value for item in Privilege), str(spec.get("mpp") or "M"))


def _mutate_pmp_permissions(spec: dict[str, Any], rng: Random) -> None:
    entry = _select_mutable_entry(spec, rng)
    permission_fields = ("read", "write", "execute")
    field = permission_fields[rng.randrange(len(permission_fields))]
    entry[field] = not bool(entry.get(field))
    if not any(bool(entry.get(name)) for name in permission_fields):
        entry["read"] = True


def _mutate_pmp_address_mode(spec: dict[str, Any], rng: Random) -> None:
    entry = _select_mutable_entry(spec, rng)
    current = int(entry.get("address_mode") or 0)
    entry["address_mode"] = int(_choose_other(rng, (1, 2, 3), current))


def _mutate_pmp_entry_topology(spec: dict[str, Any], rng: Random) -> None:
    positions = _mutable_entry_positions(spec, require_two=True)
    if len(positions) < 2:
        raise ValueError("pmp-entry-topology requires at least two mutable PMP entries")
    first, second = positions[0], positions[1]
    entries = _require_list(spec, "entries")
    entries[first]["index"], entries[second]["index"] = entries[second]["index"], entries[first]["index"]


def _mutate_mseccfg(spec: dict[str, Any], rng: Random) -> None:
    mseccfg = _require_dict(spec, "mseccfg")
    field = ("mml", "mmwp", "rlb")[rng.randrange(3)]
    mseccfg[field] = not bool(mseccfg.get(field))


def _mutate_pte_permissions(spec: dict[str, Any], rng: Random, target_rwx: str | None = None) -> None:
    if spec.get("sv39") is None and not spec.get("pte_permissions"):
        raise ValueError("toggle-pte-permissions requires an Sv39 scenario")
    pte_permissions = spec.setdefault("pte_permissions", {})
    if target_rwx is not None:
        if target_rwx not in _RWX_CHOICES:
            raise ValueError(f"unsupported PTE rwx target: {target_rwx}")
        rwx = target_rwx
    else:
        current = str(pte_permissions.get("rwx") or "r--")
        rwx = _choose_other(rng, _RWX_CHOICES, current)
    _apply_rwx(spec, rwx)


def _mutate_sum_mxr_sfence(spec: dict[str, Any], rng: Random) -> None:
    field = ("sum_enabled", "mxr", "sfence_vma")[rng.randrange(3)]
    spec[field] = not bool(spec.get(field))


def _mutate_stateful_sequence(spec: dict[str, Any], rng: Random) -> None:
    sequence = spec.get("stateful_sequence")
    if not isinstance(sequence, dict):
        raise ValueError("toggle-stateful-sequence requires a stateful sequence")
    dimension = ("warmup", "mutation", "fence")[rng.randrange(3)]
    if dimension == "warmup":
        sequence["warmup"] = not bool(sequence.get("warmup"))
    elif dimension == "mutation":
        sequence["mutation"] = _choose_other(rng, _STATEFUL_MUTATIONS, str(sequence.get("mutation") or "none"))
    else:
        sequence["fence"] = _choose_other(rng, _STATEFUL_FENCES, str(sequence.get("fence") or "none"))


def _set_bool_field(spec: dict[str, Any], field: str, value: bool) -> None:
    if bool(spec.get(field)) == value:
        raise ValueError(f"{field} already set to requested value")
    spec[field] = value


def _set_entry_locked(spec: dict[str, Any], value: bool) -> None:
    entry = _select_mutable_entry(spec, Random(0))
    if bool(entry.get("locked")) == value:
        raise ValueError("requested pmp locked state already set")
    entry["locked"] = value


def _set_mseccfg_bit(spec: dict[str, Any], bit: str, value: bool) -> None:
    mseccfg = _require_dict(spec, "mseccfg")
    if bool(mseccfg.get(bit)) == value:
        raise ValueError(f"mseccfg.{bit} already set to requested value")
    mseccfg[bit] = value


def _set_stateful_field(spec: dict[str, Any], field: str, value: str, allowed: tuple[str, ...]) -> None:
    sequence = spec.get("stateful_sequence")
    if not isinstance(sequence, dict):
        raise ValueError(f"{field} requires a stateful sequence")
    if value not in allowed:
        raise ValueError(f"unsupported stateful value for {field}: {value}")
    if str(sequence.get(field) or "") == value:
        raise ValueError(f"stateful field {field} already set to requested value")
    sequence[field] = value


def _apply_rwx(spec: dict[str, Any], rwx: str) -> None:
    pte_permissions = spec.setdefault("pte_permissions", {})
    current = str(pte_permissions.get("rwx") or "")
    if current == rwx:
        raise ValueError("PTE rwx already set to requested value")
    pte_permissions["rwx"] = rwx
    pte_permissions["read"] = "r" in rwx
    pte_permissions["write"] = "w" in rwx
    pte_permissions["execute"] = "x" in rwx
    if spec.get("sv39") is not None:
        pte = _require_dict(_require_dict(spec, "sv39"), "pte")
        pte["read"] = "r" in rwx
        pte["write"] = "w" in rwx
        pte["execute"] = "x" in rwx


def _mutable_entry_positions(spec: dict[str, Any], require_two: bool = False) -> list[int]:
    positions = [
        index
        for index, entry in enumerate(_require_list(spec, "entries"))
        if int(entry.get("pmpaddr") or -1) not in _HARNESS_PMPADDRS
    ]
    if require_two and len(positions) < 2:
        return []
    return positions


def _select_mutable_entry(spec: dict[str, Any], rng: Random) -> dict[str, Any]:
    positions = _mutable_entry_positions(spec)
    if not positions:
        raise ValueError("no mutable PMP entries available")
    entries = _require_list(spec, "entries")
    return entries[positions[rng.randrange(len(positions))]]


def _choose_other(rng: Random, choices: Iterable[Any], current: Any) -> Any:
    options = [item for item in choices if item != current]
    if not options:
        raise ValueError("no alternative value available")
    return options[rng.randrange(len(options))]


def _parse_bool_digit(value: str) -> bool:
    if value == "1":
        return True
    if value == "0":
        return False
    raise ValueError(f"expected boolean digit 0/1, got {value}")


def _require_dict(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value


def _require_list(mapping: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = mapping.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return value
