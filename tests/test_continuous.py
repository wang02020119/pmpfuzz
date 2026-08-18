import copy
import unittest

from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.scenario_codec import scenario_hash, scenario_to_spec


class ScenarioStreamTest(unittest.TestCase):
    def test_generate_root_is_deterministic(self):
        stream = ScenarioStream(root_seed=20260714)

        first = scenario_to_spec(stream.generate_root(0))
        second = scenario_to_spec(stream.generate_root(0))

        self.assertEqual(first, second)
        self.assertEqual(scenario_hash(first), scenario_hash(second))

    def test_generate_root_varies_by_sequence(self):
        stream = ScenarioStream(root_seed=20260714)

        first = scenario_to_spec(stream.generate_root(0))
        second = scenario_to_spec(stream.generate_root(1))

        self.assertNotEqual(scenario_hash(first), scenario_hash(second))

    def test_mutate_toggle_access_is_deterministic_and_changes_hash(self):
        stream = ScenarioStream(root_seed=99, profiles=("pmp-boundary",))
        parent_spec = scenario_to_spec(stream.generate_root(0))

        mutated_a = scenario_to_spec(stream.mutate(parent_spec, "toggle-access", 0))
        mutated_b = scenario_to_spec(stream.mutate(parent_spec, "toggle-access", 0))

        self.assertEqual(mutated_a, mutated_b)
        self.assertNotEqual(scenario_hash(parent_spec), scenario_hash(mutated_a))

    def test_mutate_does_not_modify_parent_spec(self):
        stream = ScenarioStream(root_seed=101, profiles=("sv39-ptw-pmp-matrix",))
        parent_spec = scenario_to_spec(stream.generate_root(0))
        snapshot = copy.deepcopy(parent_spec)

        stream.mutate(parent_spec, "toggle-pte-permissions", 0)

        self.assertEqual(parent_spec, snapshot)

    def test_mutate_rejects_inapplicable_stateful_operator(self):
        stream = ScenarioStream(root_seed=7, profiles=("pmp-boundary",))
        parent_spec = scenario_to_spec(stream.generate_root(0))

        with self.assertRaises(ValueError):
            stream.mutate(parent_spec, "toggle-stateful-sequence", 0)

    def test_feedback_style_operator_sets_target_value(self):
        stream = ScenarioStream(root_seed=13, profiles=("sv39-ptw-pmp-matrix",))
        parent_spec = scenario_to_spec(stream.generate_root(0))

        mutated = scenario_to_spec(stream.mutate(parent_spec, "set-pte-rwx=rw-", 0))

        self.assertEqual(mutated["pte_permissions"]["rwx"], "rw-")
        self.assertTrue(mutated["sv39"]["pte"]["read"])
        self.assertTrue(mutated["sv39"]["pte"]["write"])
        self.assertFalse(mutated["sv39"]["pte"]["execute"])


if __name__ == "__main__":
    unittest.main()
