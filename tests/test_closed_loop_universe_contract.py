import unittest

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.coverage_universe import make_coverage_universe
from scripts.evaluation.campaigns.run_closed_loop_campaign import CampaignState, _schedule_entry


def _bundle():
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["sem:0", "sem:1"],
            capability_fingerprint="cap-a",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:0"],
            capability_fingerprint="cap-a",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=["combo3:0"],
            capability_fingerprint="cap-a",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:0"],
            capability_fingerprint="cap-a",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
        ),
    }


class ClosedLoopUniverseContractTest(unittest.TestCase):
    def test_campaign_state_uses_frozen_universe_denominators(self):
        state = CampaignState(
            "camp",
            "random",
            "rocket-clean",
            101,
            "semantic",
            candidate_pool=[
                {
                    "candidate_id": "a",
                    "semantic_bins": ["sem:0"],
                    "pairwise_bins": [],
                    "security_triple_bins": [],
                    "predicate_bins": [],
                }
            ],
            start_time=0.0,
            coverage_universes=_bundle(),
        )

        state.record_case(
            candidate_id="a",
            case_id="case-a",
            profile="pmp-boundary",
            status="pass",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=1.0,
            case_elapsed=0.1,
            new_semantic=1,
            new_pairwise=0,
            new_triples=0,
            new_predicates=0,
            new_whitebox=0,
            case_semantic={"sem:0"},
            case_pairwise=set(),
            case_triples=set(),
            case_predicates=set(),
        )

        self.assertEqual(state._timeline_lines[-1]["semantic_target"], 2)

    def test_update_coverage_sets_ignores_out_of_contract_bins(self):
        state = CampaignState(
            "camp",
            "random",
            "rocket-clean",
            101,
            "semantic",
            candidate_pool=[],
            start_time=0.0,
            coverage_universes=_bundle(),
        )

        ns, np, nt, npr = state.update_coverage_sets(
            {"sem:0", "sem:outside"},
            {"combo2:outside"},
            {"combo3:0"},
            {"pred:outside"},
            eligible=True,
        )

        self.assertEqual((ns, np, nt, npr), (1, 0, 1, 0))

    def test_schedule_entry_preserves_embedded_scenario_spec(self):
        candidate = {
            "candidate_id": "cand-1",
            "profile": "pmp-boundary",
            "scenario_index": 0,
            "name": "scenario_0000",
            "selection_source": "random",
            "estimated_new_bins": 0,
            "scenario_spec": {"schema_version": 1, "name": "scenario_0000"},
            "scenario_hash": "a" * 64,
        }

        entry = _schedule_entry(candidate, 20260628)

        self.assertEqual(entry["scenario_spec"], candidate["scenario_spec"])
        self.assertEqual(entry["scenario_hash"], candidate["scenario_hash"])

    def test_campaign_state_uses_frozen_bapc_denominator(self):
        bapc_universe = build_bapc_coverage_universe(
            dut="xiangshan-clean",
            generator_seed=20260715,
            supports_fault_stage=True,
            supports_smepmp=False,
        )
        target_bin = str(bapc_universe["bin_ids"][0])
        state = CampaignState(
            "camp",
            "random",
            "xiangshan-clean",
            101,
            "bapc",
            candidate_pool=[{"candidate_id": "b", "bapc_bins": [target_bin]}],
            start_time=0.0,
            coverage_universes={**_bundle(), "bapc": bapc_universe},
        )

        state.record_case(
            candidate_id="b",
            case_id="case-b",
            profile="pmp-boundary",
            status="observed",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=1.0,
            case_elapsed=0.1,
            new_semantic=0,
            new_pairwise=0,
            new_triples=0,
            new_predicates=0,
            new_whitebox=0,
            new_bapc=1,
            bapc_eligible=True,
            case_bapc={target_bin},
            case_semantic=set(),
            case_pairwise=set(),
            case_triples=set(),
            case_predicates=set(),
        )

        self.assertEqual(state._timeline_lines[-1]["bapc_target"], 208)
        self.assertEqual(state._timeline_lines[-1]["bapc_covered"], 1)

    def test_campaign_state_uses_selected_bapc_v3_denominator(self):
        bapc_universe = build_bapc_coverage_universe(
            dut="xiangshan-clean",
            generator_seed=20260715,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        target_bin = str(bapc_universe["bin_ids"][0])
        state = CampaignState(
            "camp",
            "random",
            "xiangshan-clean",
            101,
            "bapc",
            candidate_pool=[{"candidate_id": "b", "bapc_bins": [target_bin]}],
            start_time=0.0,
            coverage_universes={**_bundle(), "bapc": bapc_universe},
        )

        state.record_case(
            candidate_id="b",
            case_id="case-b",
            profile="pmp-boundary",
            status="observed",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=1.0,
            case_elapsed=0.1,
            new_semantic=0,
            new_pairwise=0,
            new_triples=0,
            new_predicates=0,
            new_whitebox=0,
            new_bapc=1,
            bapc_eligible=True,
            case_bapc={target_bin},
            case_semantic=set(),
            case_pairwise=set(),
            case_triples=set(),
            case_predicates=set(),
        )

        self.assertEqual(state._timeline_lines[-1]["bapc_target"], 129)
        self.assertEqual(state._timeline_lines[-1]["bapc_covered"], 1)


if __name__ == "__main__":
    unittest.main()
