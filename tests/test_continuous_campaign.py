import unittest

from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.continuous_campaign import ContinuousQueueManager, candidate_record_from_dict
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4


def _universes():
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["sem:0", "sem:1", "sem:2"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=["combo3:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
    }


class ContinuousQueueManagerTest(unittest.TestCase):
    def test_real_toggle_pmp_permissions_noop_returns_parent_semantics(self):
        stream = ScenarioStream(root_seed=1, profiles=("pmp-boundary",))
        parent = stream.generate_root(2)
        parent_spec = scenario_to_spec(parent)
        parent_hash = scenario_hash(parent_spec)

        child = stream.mutate(parent_spec, "toggle-pmp-permissions", 8)

        self.assertEqual(scenario_hash(scenario_to_spec(child)), parent_hash)

    def test_fill_pending_treats_no_semantic_change_as_rejection_and_continues(self):
        class NoOpThenChildStream:
            def __init__(self):
                self.root_seed = 1
                self._base = ScenarioStream(root_seed=1, profiles=("pmp-boundary",))
                self._parent = self._base.generate_root(2)

            def generate_root(self, sequence: int):
                if sequence == 0:
                    return self._parent
                return self._base.generate_root(sequence + 10)

            def applicable_operators(self, parent_spec):
                return ("synthetic-no-op",)

            def mutate(self, parent_spec, operator, attempt):
                if attempt == 0:
                    return scenario_from_spec(parent_spec)
                return self._base.mutate(parent_spec, "toggle-access", attempt)

        manager = ContinuousQueueManager(
            variant="random-mutation",
            stream=NoOpThenChildStream(),
            coverage_universes=_universes(),
            scheduler_seed=31,
            pending_limit=8,
            corpus_limit=4,
        )

        manager.fill_pending(1)
        parent = manager.pop_batch(1)[0]
        manager.record_execution(
            parent,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        generated = manager.fill_pending(1)
        attempts = manager.consume_generation_attempts()

        self.assertEqual(len(generated), 1)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0].rejected_reason, "mutation-no-semantic-change")
        self.assertEqual(attempts[0].record.parent_hash, parent.scenario_hash)
        self.assertIsNone(attempts[1].rejected_reason)
        self.assertEqual(attempts[1].record.mutation_seed, 1)
        self.assertEqual(generated[0].parent_hash, parent.scenario_hash)

    def test_multiple_noops_consume_attempts_without_looping_forever(self):
        class TripleNoOpStream:
            def __init__(self):
                self.root_seed = 1
                self._base = ScenarioStream(root_seed=1, profiles=("pmp-boundary",))
                self._parent = self._base.generate_root(2)

            def generate_root(self, sequence: int):
                if sequence == 0:
                    return self._parent
                return self._base.generate_root(sequence + 20)

            def applicable_operators(self, parent_spec):
                return ("synthetic-no-op",)

            def mutate(self, parent_spec, operator, attempt):
                if attempt < 3:
                    return scenario_from_spec(parent_spec)
                return self._base.mutate(parent_spec, "toggle-access", attempt)

        manager = ContinuousQueueManager(
            variant="random-mutation",
            stream=TripleNoOpStream(),
            coverage_universes=_universes(),
            scheduler_seed=32,
            pending_limit=8,
            corpus_limit=4,
        )

        manager.fill_pending(1)
        parent = manager.pop_batch(1)[0]
        manager.record_execution(
            parent,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        generated = manager.fill_pending(1)
        attempts = manager.consume_generation_attempts()

        self.assertEqual(len(generated), 1)
        self.assertEqual(len(attempts), 4)
        self.assertEqual(
            [attempt.rejected_reason for attempt in attempts[:3]],
            ["mutation-no-semantic-change"] * 3,
        )
        self.assertEqual(attempts[-1].record.mutation_seed, 3)
        self.assertEqual(generated[0].parent_hash, parent.scenario_hash)

    def test_fill_pending_skips_invalid_stateful_candidates_and_records_rejection(self):
        class RejectingWarmupStream:
            def __init__(self):
                self.root_seed = 21
                self._fallback = ScenarioStream(root_seed=21, profiles=("pmp-boundary",))

            def generate_root(self, sequence: int):
                if sequence == 0:
                    scenario = ScenarioGenerator(seed=21, include_smepmp=False, profile="pmp-side-effect").generate_one(1)
                    spec = scenario_to_spec(scenario)
                    aligned_address = spec["probe"]["physical_address"] & ~0x3
                    spec["access"] = "store"
                    spec["probe"]["size"] = 4
                    spec["probe"]["physical_address"] = aligned_address
                    spec["probe"]["virtual_address"] = aligned_address
                    spec["stateful_sequence"]["warmup"] = True
                    spec["stateful_sequence"]["warmup_access"] = "store"
                    spec["stateful_sequence"].setdefault("sentinel", {})["physical_address"] = aligned_address
                    return scenario_from_spec(spec)
                return self._fallback.generate_root(sequence)

            def applicable_operators(self, parent_spec):
                return ()

        manager = ContinuousQueueManager(
            variant="random-fresh",
            stream=RejectingWarmupStream(),
            coverage_universes=_universes(),
            scheduler_seed=21,
            pending_limit=8,
            corpus_limit=4,
        )

        generated = manager.fill_pending(1)
        attempts = manager.consume_generation_attempts()

        self.assertEqual(len(generated), 1)
        self.assertEqual(len(manager.pending), 1)
        self.assertEqual(len(attempts), 2)
        self.assertIsNotNone(attempts[0].rejected_reason)
        self.assertIn("store", attempts[0].rejected_reason)
        self.assertIsNone(attempts[1].rejected_reason)

    def test_random_fresh_generates_unique_pending_candidates(self):
        manager = ContinuousQueueManager(
            variant="random-fresh",
            stream=ScenarioStream(root_seed=1, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=7,
            pending_limit=8,
            corpus_limit=4,
        )

        manager.fill_pending(3)

        self.assertEqual(len(manager.pending), 3)
        self.assertEqual(len({item.scenario_hash for item in manager.pending}), 3)
        self.assertEqual(len(manager.corpus_entries), 0)

    def test_random_mutation_promotes_only_when_new_bins_found(self):
        manager = ContinuousQueueManager(
            variant="random-mutation",
            stream=ScenarioStream(root_seed=2, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=8,
            pending_limit=8,
            corpus_limit=4,
        )

        manager.fill_pending(1)
        candidate = manager.pop_batch(1)[0]
        manager.record_execution(
            candidate,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        self.assertIn(candidate.scenario_hash, manager.corpus_entries)

        manager.fill_pending(1)
        child = manager.pop_batch(1)[0]
        self.assertEqual(child.parent_hash, candidate.scenario_hash)
        self.assertEqual(child.mutation_depth, 1)

        manager.record_execution(
            child,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )
        self.assertIn(child.scenario_hash, manager.corpus_entries)

    def test_ineligible_execution_does_not_promote(self):
        manager = ContinuousQueueManager(
            variant="random-mutation",
            stream=ScenarioStream(root_seed=3, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=9,
            pending_limit=8,
            corpus_limit=4,
        )

        manager.fill_pending(1)
        candidate = manager.pop_batch(1)[0]
        manager.record_execution(
            candidate,
            eligible=False,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        self.assertEqual(manager.corpus_entries, {})

    def test_bb_guided_uses_active_coverage_mode_for_energy(self):
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=4, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=10,
            pending_limit=8,
            corpus_limit=4,
            coverage_mode="predicates",
        )

        manager.fill_pending(2)
        first, second = manager.pop_batch(2)
        first_summary = manager.record_execution(
            first,
            eligible=True,
            observed_bins={"semantic": ["sem:0", "sem:1"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )
        second_summary = manager.record_execution(
            second,
            eligible=True,
            observed_bins={"semantic": [], "pairwise": [], "security_triples": [], "predicates": ["pred:0"]},
            execution_cost=1.0,
        )

        self.assertTrue(first_summary["promoted"])
        self.assertTrue(second_summary["promoted"])
        self.assertLess(
            manager.corpus_entries[first.scenario_hash].energy,
            manager.corpus_entries[second.scenario_hash].energy,
        )

    def test_bb_guided_retains_neutral_intermediate_seed(self):
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=5, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=11,
            pending_limit=8,
            corpus_limit=4,
            coverage_mode="semantic",
        )

        manager.fill_pending(1)
        parent = manager.pop_batch(1)[0]
        manager.record_execution(
            parent,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        manager.fill_pending(1)
        child = manager.pop_batch(1)[0]
        summary = manager.record_execution(
            child,
            eligible=True,
            observed_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            execution_cost=1.0,
        )

        self.assertTrue(summary["promoted"])
        self.assertIn(child.scenario_hash, manager.corpus_entries)

    def test_resume_recovers_root_collision_counters_before_next_success(self):
        class CollidingRootStream:
            def __init__(self):
                self.root_seed = 17
                self._base = ScenarioStream(root_seed=17, profiles=("pmp-boundary",))

            def generate_root(self, sequence: int):
                source = 0 if sequence < 2 else sequence - 1
                return self._base.generate_root(source)

            def applicable_operators(self, parent_spec):
                return ()

        direct = ContinuousQueueManager(
            variant="random-fresh",
            stream=CollidingRootStream(),
            coverage_universes=_universes(),
            scheduler_seed=12,
            pending_limit=8,
            corpus_limit=4,
        )
        accepted = direct.fill_pending(2)
        attempts = direct.consume_generation_attempts()

        resumed = ContinuousQueueManager(
            variant="random-fresh",
            stream=CollidingRootStream(),
            coverage_universes=_universes(),
            scheduler_seed=12,
            pending_limit=8,
            corpus_limit=4,
        )

        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_generated",
                scenario_hash=attempts[0].record.scenario_hash,
                scenario_spec=attempts[0].record.scenario_spec,
                generation_seq=attempts[0].record.generation_seq,
                parent_hash=attempts[0].record.parent_hash,
                mutation_operator=attempts[0].record.mutation_operator,
                mutation_seed=attempts[0].record.mutation_seed,
                mutation_depth=attempts[0].record.mutation_depth,
                root_sequence=attempts[0].record.root_sequence,
            )
            writer.append("candidate_queued", scenario_hash=attempts[0].record.scenario_hash)
            writer.append(
                "candidate_duplicate",
                scenario_hash=attempts[1].record.scenario_hash,
                scenario_spec=attempts[1].record.scenario_spec,
                generation_seq=attempts[1].record.generation_seq,
                parent_hash=attempts[1].record.parent_hash,
                mutation_operator=attempts[1].record.mutation_operator,
                mutation_seed=attempts[1].record.mutation_seed,
                mutation_depth=attempts[1].record.mutation_depth,
                root_sequence=attempts[1].record.root_sequence,
            )
            recovered = recover_schedule_v4(path)

        resumed.restore_runtime_state(
            seen_hashes=recovered.seen_hashes,
            coverage_state=recovered.coverage_state,
            next_generation_seq=recovered.next_generation_seq,
            next_mutation_attempt=recovered.next_mutation_attempt,
            next_root_sequence=recovered.next_root_sequence,
        )
        resumed.restore_records(
            pending_records=[candidate_record_from_dict(recovered.candidate_records[attempts[0].record.scenario_hash])],
            corpus_records=[],
        )
        resumed.fill_pending(2)
        resumed_attempts = resumed.consume_generation_attempts()

        self.assertEqual(accepted[1].scenario_hash, resumed_attempts[0].record.scenario_hash)
        self.assertEqual(attempts[2].record.generation_seq, resumed_attempts[0].record.generation_seq)
        self.assertEqual(attempts[2].record.root_sequence, resumed_attempts[0].record.root_sequence)


if __name__ == "__main__":
    unittest.main()
