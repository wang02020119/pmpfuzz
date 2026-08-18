from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any

from .continuous import ScenarioStream
from .coverage_universe import classify_observed_bins, validate_coverage_universe
from .scenario_codec import scenario_hash, scenario_to_spec
from .stateful import validate_stateful_contract


VALID_VARIANTS = frozenset({"random-fresh", "random-mutation", "bb-guided"})
DEFAULT_COVERAGE_MODES = ("semantic", "pairwise", "security_triples", "predicates")


@dataclass
class CandidateRecord:
    scenario_hash: str
    scenario_spec: dict[str, Any]
    parent_hash: str | None
    mutation_operator: str
    mutation_seed: int
    generation_seq: int
    mutation_depth: int
    generation_seed: int = 0
    scenario_index: int | None = None
    generator_variant: str = "full"
    root_sequence: int | None = None


@dataclass
class CandidateAttempt:
    record: CandidateRecord
    duplicate: bool = False
    rejected_reason: str | None = None


@dataclass
class CorpusEntry:
    candidate: CandidateRecord
    selection_count: int = 0
    execution_cost: float = 0.0
    energy: float = 1.0
    retained_without_novelty: bool = False
    discovered_bins: dict[str, list[str]] = field(default_factory=dict)


class ContinuousQueueManager:
    def __init__(
        self,
        *,
        variant: str,
        stream: ScenarioStream,
        coverage_universes: dict[str, dict[str, Any]],
        scheduler_seed: int,
        pending_limit: int,
        corpus_limit: int,
        coverage_mode: str = "semantic",
    ) -> None:
        if variant not in VALID_VARIANTS:
            raise ValueError(f"unsupported continuous variant: {variant}")
        self.variant = variant
        self.stream = stream
        self.scheduler_seed = int(scheduler_seed)
        self.pending_limit = int(pending_limit)
        self.corpus_limit = int(corpus_limit)
        self.coverage_universes = {
            mode: validate_coverage_universe(universe)
            for mode, universe in coverage_universes.items()
        }
        self.coverage_mode = _normalize_coverage_mode(coverage_mode)
        self.coverage_state = {
            mode: set()
            for mode in self.coverage_universes
        }
        self.pending: list[CandidateRecord] = []
        self.corpus_entries: dict[str, CorpusEntry] = {}
        self.seen_hashes: set[str] = set()
        self._recent_attempts: list[CandidateAttempt] = []
        self._root_sequence = 0
        self._generation_seq = 0
        self._mutation_attempt = 0

    def fill_pending(self, low_watermark: int) -> list[CandidateRecord]:
        target = min(int(low_watermark), self.pending_limit)
        attempts = 0
        generated: list[CandidateRecord] = []
        self._recent_attempts = []
        while len(self.pending) < target and attempts < target * 32 + 32:
            attempts += 1
            attempt = self._next_candidate()
            if attempt is None:
                continue
            candidate = attempt.record
            attempt.duplicate = candidate.scenario_hash in self.seen_hashes
            self._recent_attempts.append(attempt)
            if candidate.parent_hash is not None and candidate.parent_hash in self.corpus_entries:
                self.corpus_entries[candidate.parent_hash].selection_count += 1
            if attempt.rejected_reason is not None or attempt.duplicate:
                continue
            self.pending.append(candidate)
            self.seen_hashes.add(candidate.scenario_hash)
            generated.append(candidate)
        return generated

    def consume_generation_attempts(self) -> list[CandidateAttempt]:
        attempts = list(self._recent_attempts)
        self._recent_attempts = []
        return attempts

    def restore_runtime_state(
        self,
        *,
        seen_hashes: set[str],
        coverage_state: dict[str, set[str]],
        next_generation_seq: int = 0,
        next_mutation_attempt: int = 0,
        next_root_sequence: int = 0,
    ) -> None:
        self.seen_hashes = set(seen_hashes)
        for mode in self.coverage_state:
            self.coverage_state[mode] = set(coverage_state.get(mode) or set())
        self._generation_seq = int(next_generation_seq)
        self._mutation_attempt = int(next_mutation_attempt)
        self._root_sequence = int(next_root_sequence)

    def restore_records(
        self,
        *,
        pending_records: list[CandidateRecord],
        corpus_records: list[tuple[CandidateRecord, dict[str, list[str]], float, int, bool]],
    ) -> None:
        self.pending = list(pending_records)
        self.corpus_entries = {}
        for candidate, discovered_bins, execution_cost, selection_count, retained_without_novelty in corpus_records:
            normalized = {
                mode: sorted(set(discovered_bins.get(mode) or []))
                for mode in self.coverage_universes
            }
            energy = self._energy_for_discovered(normalized, retained_without_novelty=retained_without_novelty)
            self.corpus_entries[candidate.scenario_hash] = CorpusEntry(
                candidate=candidate,
                selection_count=int(selection_count),
                execution_cost=float(execution_cost),
                energy=energy if energy > 0.0 else self._neutral_energy_floor(),
                retained_without_novelty=bool(retained_without_novelty),
                discovered_bins=normalized,
            )

    def pop_batch(self, count: int) -> list[CandidateRecord]:
        batch = self.pending[:count]
        self.pending = self.pending[count:]
        return batch

    def choose_parent_for_mutation(self) -> CandidateRecord:
        if not self.corpus_entries:
            raise ValueError("no corpus entries available")
        entries = sorted(self.corpus_entries.values(), key=lambda item: item.candidate.scenario_hash)
        if self.variant == "random-mutation":
            chosen = entries[self._decision_index("random-parent", len(entries), self._mutation_attempt)]
        else:
            chosen = self._weighted_choice(entries, decision_kind="bb-guided-parent")
        return chosen.candidate

    def record_execution(
        self,
        candidate: CandidateRecord,
        *,
        eligible: bool,
        observed_bins: dict[str, list[str] | set[str]],
        execution_cost: float,
    ) -> dict[str, Any]:
        summary = self.prepare_execution(
            candidate,
            eligible=eligible,
            observed_bins=observed_bins,
            execution_cost=execution_cost,
        )
        self.commit_execution(candidate, summary)
        return summary

    def prepare_execution(
        self,
        candidate: CandidateRecord,
        *,
        eligible: bool,
        observed_bins: dict[str, list[str] | set[str]],
        execution_cost: float,
    ) -> dict[str, Any]:
        discovered = {mode: [] for mode in self.coverage_universes}
        summary = {
            "discovered_bins": discovered,
            "promoted": False,
            "evicted_hashes": [],
            "retained_without_novelty": False,
            "corpus_entry": None,
        }
        if not eligible:
            return summary

        for mode in discovered:
            classified = classify_observed_bins(self.coverage_universes[mode], observed_bins.get(mode) or [])
            new_bins = sorted(set(classified["covered"]) - self.coverage_state[mode])
            discovered[mode] = new_bins

        active_novelty = len(discovered[self.coverage_mode])
        retain_neutral = self.variant == "bb-guided" and active_novelty == 0
        promote = self.variant in {"random-mutation", "bb-guided"}
        if promote:
            energy = self._energy_for_discovered(
                discovered,
                retained_without_novelty=retain_neutral,
            )
            entry = CorpusEntry(
                candidate=candidate,
                execution_cost=float(execution_cost),
                energy=energy if energy > 0.0 else self._neutral_energy_floor(),
                retained_without_novelty=retain_neutral,
                discovered_bins=discovered,
            )
            shadow_entries = dict(self.corpus_entries)
            shadow_entries[candidate.scenario_hash] = entry
            summary["promoted"] = True
            summary["retained_without_novelty"] = retain_neutral
            summary["corpus_entry"] = entry
            summary["evicted_hashes"] = self._enforce_corpus_limit_on(shadow_entries)
        return summary

    def commit_execution(self, candidate: CandidateRecord, summary: dict[str, Any]) -> None:
        for mode in self.coverage_state:
            self.coverage_state[mode].update(summary["discovered_bins"].get(mode) or [])
        if not summary["promoted"]:
            return
        entry = summary.get("corpus_entry")
        if not isinstance(entry, CorpusEntry):
            return
        self.corpus_entries[candidate.scenario_hash] = entry
        self._enforce_corpus_limit()

    def _next_candidate(self) -> CandidateAttempt | None:
        if self.variant == "random-fresh" or not self.corpus_entries:
            root_sequence = self._root_sequence
            root_seed = int(getattr(self.stream, "root_seed", root_sequence))
            generator_variant = str(getattr(self.stream, "generator_variant", "full") or "full")
            if hasattr(self.stream, "generate_root_with_metadata"):
                generated = self.stream.generate_root_with_metadata(root_sequence)
                scenario = generated.scenario
                generation_seed = int(generated.generation_seed)
                scenario_index = generated.scenario_index
                generator_variant = str(generated.generator_variant or generator_variant)
            else:
                scenario = self.stream.generate_root(root_sequence)
                generation_seed = root_seed
                scenario_index = root_sequence
            self._root_sequence += 1
            record = self._make_record(
                scenario_spec=scenario_to_spec(scenario),
                parent_hash=None,
                mutation_operator="root",
                mutation_depth=0,
                mutation_seed=root_seed,
                generation_seed=generation_seed,
                scenario_index=scenario_index,
                generator_variant=generator_variant,
                root_sequence=root_sequence,
            )
            valid, reason = validate_stateful_contract(scenario)
            return CandidateAttempt(record=record, rejected_reason=None if valid else reason)

        parent = self.choose_parent_for_mutation()
        operators = self.stream.applicable_operators(parent.scenario_spec)
        if not operators:
            return None
        operator = operators[self._decision_index("operator", len(operators), self._mutation_attempt, parent.scenario_hash)]
        mutation_seed = self._mutation_attempt
        self._mutation_attempt += 1
        scenario = self.stream.mutate(parent.scenario_spec, operator, mutation_seed)
        generator_variant = str(getattr(self.stream, "generator_variant", "full") or "full")
        if hasattr(self.stream, "mutation_generation_seed"):
            generation_seed = self.stream.mutation_generation_seed(parent.scenario_hash, operator, mutation_seed)
        else:
            generation_seed = mutation_seed
        record = self._make_record(
            scenario_spec=scenario_to_spec(scenario),
            parent_hash=parent.scenario_hash,
            mutation_operator=operator,
            mutation_depth=parent.mutation_depth + 1,
            mutation_seed=mutation_seed,
            generation_seed=generation_seed,
            scenario_index=None,
            generator_variant=generator_variant,
            root_sequence=None,
        )
        if record.scenario_hash == parent.scenario_hash:
            return CandidateAttempt(
                record=record,
                rejected_reason="mutation-no-semantic-change",
            )
        valid, reason = validate_stateful_contract(scenario)
        return CandidateAttempt(record=record, rejected_reason=None if valid else reason)

    def _make_record(
        self,
        *,
        scenario_spec: dict[str, Any],
        parent_hash: str | None,
        mutation_operator: str,
        mutation_depth: int,
        mutation_seed: int,
        generation_seed: int,
        scenario_index: int | None,
        generator_variant: str,
        root_sequence: int | None,
    ) -> CandidateRecord:
        self._generation_seq += 1
        spec_hash = scenario_hash(scenario_spec)
        return CandidateRecord(
            scenario_hash=spec_hash,
            scenario_spec=scenario_spec,
            parent_hash=parent_hash,
            mutation_operator=mutation_operator,
            mutation_seed=int(mutation_seed),
            generation_seed=int(generation_seed),
            scenario_index=scenario_index,
            generation_seq=self._generation_seq,
            mutation_depth=int(mutation_depth),
            generator_variant=str(generator_variant),
            root_sequence=root_sequence,
        )

    def _enforce_corpus_limit(self) -> list[str]:
        return self._enforce_corpus_limit_on(self.corpus_entries)

    def _enforce_corpus_limit_on(self, entries: dict[str, CorpusEntry]) -> list[str]:
        evicted: list[str] = []
        while len(entries) > self.corpus_limit:
            victim = min(
                entries.values(),
                key=lambda item: (
                    item.candidate.generation_seq,
                    item.candidate.scenario_hash,
                ),
            )
            evicted.append(victim.candidate.scenario_hash)
            del entries[victim.candidate.scenario_hash]
        return evicted

    def _energy_for_discovered(
        self,
        discovered: dict[str, list[str]],
        *,
        retained_without_novelty: bool = False,
    ) -> float:
        if retained_without_novelty:
            return self._neutral_energy_floor()
        universe = self.coverage_universes[self.coverage_mode]
        total_bins = max(1, len(universe["bin_ids"]))
        active_new = len(discovered.get(self.coverage_mode) or [])
        return active_new / total_bins

    def _neutral_energy_floor(self) -> float:
        total_bins = max(1, len(self.coverage_universes[self.coverage_mode]["bin_ids"]))
        return 1.0 / (total_bins * 1000.0)

    def _weighted_choice(self, entries: list[CorpusEntry], *, decision_kind: str) -> CorpusEntry:
        weights = [
            max(item.energy, self._neutral_energy_floor()) / (1.0 + float(item.selection_count))
            for item in entries
        ]
        total = sum(weights)
        if total <= 0.0:
            return entries[self._decision_index(decision_kind, len(entries), self._mutation_attempt)]
        ticket = _decision_float(self.scheduler_seed, decision_kind, self._mutation_attempt)
        threshold = ticket * total
        cumulative = 0.0
        for entry, weight in zip(entries, weights):
            cumulative += weight
            if threshold <= cumulative:
                return entry
        return entries[-1]

    def _decision_index(self, decision_kind: str, modulo: int, *parts: object) -> int:
        if modulo <= 0:
            raise ValueError("modulo must be positive")
        return _decision_seed(self.scheduler_seed, decision_kind, *parts) % modulo


def candidate_record_from_dict(payload: dict[str, Any]) -> CandidateRecord:
    return CandidateRecord(
        scenario_hash=str(payload["scenario_hash"]),
        scenario_spec=dict(payload["scenario_spec"]),
        parent_hash=payload.get("parent_hash"),
        mutation_operator=str(payload.get("mutation_operator") or ""),
        mutation_seed=int(payload.get("mutation_seed") or 0),
        generation_seed=int(payload.get("generation_seed") or payload.get("mutation_seed") or 0),
        scenario_index=payload.get("scenario_index"),
        generation_seq=int(payload.get("generation_seq") or 0),
        mutation_depth=int(payload.get("mutation_depth") or 0),
        generator_variant=str(payload.get("generator_variant") or "full"),
        root_sequence=payload.get("root_sequence"),
    )


def _normalize_coverage_mode(coverage_mode: str) -> str:
    normalized = str(coverage_mode).replace("-", "_")
    if normalized not in {"semantic", "pairwise", "security_triples", "predicates", "hpm", "bapc"}:
        raise ValueError(f"unsupported coverage mode: {coverage_mode}")
    return normalized


def _decision_seed(seed: int, decision_kind: str, *parts: object) -> int:
    digest = hashlib.sha256()
    digest.update(str(seed).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(decision_kind).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(str(part).encode("ascii"))
    return int.from_bytes(digest.digest()[:8], byteorder="big", signed=False)


def _decision_float(seed: int, decision_kind: str, *parts: object) -> float:
    return _decision_seed(seed, decision_kind, *parts) / float(1 << 64)
