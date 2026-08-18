import unittest

from pmpfuzz.capabilities import capability_for_dut
from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.continuous_campaign import ContinuousQueueManager
from pmpfuzz.coverage_universe import freeze_coverage_universes
from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from pmpfuzz.schema import scenario_to_case_dict
from pmpfuzz.semantic_coverage import CORE_STATEFUL_TARGET
from scripts.evaluation.campaigns.run_closed_loop_campaign import (
    _continuous_candidate_dict,
    _schedule_entry,
    build_parser,
)


class SemgenAblationTests(unittest.TestCase):
    def _coverage_universes(self, seed):
        return freeze_coverage_universes(
            target=CORE_STATEFUL_TARGET,
            capability=capability_for_dut("spike", available=True),
            seed=seed,
        )

    def test_syntax_generator_emits_valid_roundtrippable_scenarios(self):
        emitter = AssemblyEmitter()
        generator = ScenarioGenerator(
            seed=17,
            include_smepmp=False,
            profile="pmp-boundary",
            generator_variant="syntax",
        )

        syntax_hashes = set()
        for index in range(32):
            scenario = generator.generate_one(index)
            spec = scenario_to_spec(scenario)
            rebuilt = scenario_from_spec(spec)
            rebuilt_spec = scenario_to_spec(rebuilt)

            self.assertEqual(scenario_hash(spec), scenario_hash(rebuilt_spec))
            self.assertEqual(rebuilt_spec["profile"], "pmp-boundary")
            self.assertGreater(len(emitter.emit(rebuilt)), 200)
            syntax_hashes.add(scenario_hash(spec))

        full_hashes = {
            scenario_hash(
                scenario_to_spec(
                    ScenarioGenerator(
                        seed=17,
                        include_smepmp=False,
                        profile="pmp-boundary",
                        generator_variant="full",
                    ).generate_one(index)
                )
            )
            for index in range(32)
        }
        self.assertNotEqual(syntax_hashes, full_hashes)

    def test_root_metadata_stays_stable_between_full_and_syntax_variants(self):
        full = ScenarioStream(root_seed=11, profiles=("pmp-boundary",), generator_variant="full")
        syntax = ScenarioStream(root_seed=11, profiles=("pmp-boundary",), generator_variant="syntax")

        full_generated = full.generate_root_with_metadata(0)
        syntax_generated = syntax.generate_root_with_metadata(0)

        self.assertEqual(full_generated.generation_seed, syntax_generated.generation_seed)
        self.assertEqual(full_generated.scenario_index, syntax_generated.scenario_index)
        self.assertEqual(full_generated.profile, syntax_generated.profile)
        self.assertNotEqual(
            scenario_hash(scenario_to_spec(full_generated.scenario)),
            scenario_hash(scenario_to_spec(syntax_generated.scenario)),
        )

    def test_continuous_records_keep_generator_provenance(self):
        universe = self._coverage_universes(seed=3)
        stream = ScenarioStream(
            root_seed=3,
            profiles=("pmp-boundary",),
            generator_variant="syntax",
        )
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=stream,
            coverage_universes=universe,
            scheduler_seed=3,
            pending_limit=8,
            corpus_limit=8,
        )

        records = manager.fill_pending(2)

        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(record.generator_variant, "syntax")
            self.assertIsInstance(record.generation_seed, int)
            self.assertIsInstance(record.scenario_index, int)

    def test_case_and_schedule_entries_include_semgen_metadata(self):
        stream = ScenarioStream(
            root_seed=5,
            profiles=("pmp-boundary",),
            generator_variant="syntax",
        )
        manager = ContinuousQueueManager(
            variant="random-fresh",
            stream=stream,
            coverage_universes=self._coverage_universes(seed=5),
            scheduler_seed=5,
            pending_limit=4,
            corpus_limit=4,
        )
        record = manager.fill_pending(1)[0]

        candidate = _continuous_candidate_dict(record, seed=5)
        entry = _schedule_entry(candidate, seed=5)
        case = scenario_to_case_dict(
            scenario_from_spec(record.scenario_spec),
            seed=5,
            index=record.generation_seq,
            generator_variant=record.generator_variant,
            generation_seed=record.generation_seed,
            scenario_index=record.scenario_index,
            mutation_operator=record.mutation_operator,
            continuous_sequence=record.generation_seq,
        )

        for payload in (candidate, entry, case):
            self.assertEqual(payload["generator_variant"], "syntax")
            self.assertEqual(payload["generation_seed"], record.generation_seed)
            self.assertEqual(payload["scenario_index"], record.scenario_index)
            self.assertEqual(payload["mutation_operator"], "root")
        self.assertEqual(entry["scenario_hash"], record.scenario_hash)
        self.assertEqual(case["continuous_sequence"], record.generation_seq)

    def test_closed_loop_parser_accepts_generator_variant_and_max_completed_cases(self):
        args = build_parser().parse_args(
            [
                "--artifact-root",
                "out",
                "--variant",
                "bb-guided",
                "--coverage-mode",
                "bapc",
                "--generator-variant",
                "syntax",
                "--max-completed-cases",
                "256",
                "--bapc-core-version",
                "v4",
            ]
        )

        self.assertEqual(args.generator_variant, "syntax")
        self.assertEqual(args.max_completed_cases, 256)
        self.assertEqual(args.bapc_core_version, "v4")


if __name__ == "__main__":
    unittest.main()
