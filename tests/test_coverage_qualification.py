"""Tests for execution-qualified coverage (RED phase).

These tests exercise the new coverage_qualification module and the
execution-coverage paths in coverage.py, semantic_coverage.py,
capabilities.py, and runner.py.
"""

import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.capabilities import (
    DEFAULT_CAPABILITY_SCHEMA_VERSION,
    capability_for_dut,
    capability_matrix,
    oracle_applicability_for_case,
)
from pmpfuzz.coverage import coverage_from_run, write_coverage
from pmpfuzz.coverage_qualification import (
    CoverageQualification,
    collect_execution_evidence,
    load_capability_map,
    load_case_map,
    load_results,
    qualify_result_for_coverage,
    read_json_file,
    result_reached_target_phase,
)
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.semantic_coverage import (
    CORE_STATEFUL_TARGET,
    build_schedule,
    coverage_gap_from_runs,
    write_schedule,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_case(seed=1, profile="pmp-boundary", include_smepmp=False):
    scenario = ScenarioGenerator(
        seed=seed, include_smepmp=include_smepmp, profile=profile
    ).generate_batch(1)[0]
    return scenario_to_case_dict(scenario, seed=seed, index=0)


def _make_result(case, dut="spike", status="pass", observation_valid=True,
                 stage_verified=True, observed_phase="completed",
                 oracle_applicability="valid", failure_class=None,
                 expected_stage_override=None, observed_event=None):
    """Build a minimal result dict as runner.py / result_to_dict would."""
    if expected_stage_override is not None:
        case = dict(case)
        case["expected"] = dict(case.get("expected") or {})
        case["expected"]["stage"] = expected_stage_override
    is_fail = status == "fail"
    if observed_event is None:
        observed_event = "trap" if is_fail else "completion"
    return result_to_dict(
        case=case,
        dut=dut,
        status=status,
        elapsed_seconds=0.1,
        returncode=0 if not is_fail else 1,
        log=Path("/tmp/case.log"),
        reason="test fixture",
        observed_tohost=0 if not is_fail else None,
        observed_mcause=5 if is_fail else None,
        observed_mtval=0xDEAD if is_fail else None,
        observed_mepc_tag=0,
        observed_mtval_fingerprint=0x1234,
        observed_event=observed_event,
        observed_phase=observed_phase,
        observed_stage="probe" if is_fail else None,
        observed_ptw_level=None,
        observed_fault_address=None,
        observation_valid=observation_valid,
        stage_verified=stage_verified,
        failure_class=failure_class,
        oracle_applicability=oracle_applicability,
    )


def _make_dut_capability(dut="spike", available=True, isa="rv64gc",
                         smepmp_supported=False, smepmp_rlb=False):
    cap = capability_for_dut(dut, available=available)
    cap["isa"] = isa
    cap["schema_version"] = 3
    cap["supported_capabilities"]["smepmp"] = smepmp_supported
    cap["supported_capabilities"]["smepmp_rlb"] = smepmp_rlb
    cap["smepmp"]["probe_status"] = "supported" if smepmp_supported else "unsupported"
    cap["smepmp"]["rlb"] = smepmp_rlb
    return cap


def _write_run_dir(run_dir, cases_results, dut_caps=None):
    """Write cases/, results/, and optionally dut_capabilities.json."""
    run_dir = Path(run_dir)
    for case_name, (case, result) in cases_results.items():
        (run_dir / "cases" / case_name).mkdir(parents=True, exist_ok=True)
        (run_dir / "results" / case_name).mkdir(parents=True, exist_ok=True)
        write_json(run_dir / "cases" / case_name / "case.json", case)
        write_json(run_dir / "results" / case_name / "result.json", result)
    if dut_caps is not None:
        write_json(run_dir / "dut_capabilities.json", dut_caps)
    write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})


# ---------------------------------------------------------------------------
# 1.  legal pass result is eligible
# ---------------------------------------------------------------------------


class LegalPassCountedTest(unittest.TestCase):
    def test_pass_with_valid_oracle_and_probe_phase_is_eligible(self):
        case = _make_case()
        # Pass means completion → observed_phase must be "completed"
        result = _make_result(case, status="pass", observed_phase="completed")
        qual = qualify_result_for_coverage(case, result)
        self.assertTrue(qual.eligible, f"expected eligible, got reason={qual.reason}")


# ---------------------------------------------------------------------------
# 2.  legal fail / mismatch result is eligible
# ---------------------------------------------------------------------------


class LegalFailCountedTest(unittest.TestCase):
    def test_fail_with_valid_mismatch_is_eligible(self):
        case = _make_case()
        # For a fail/trap mismatch, the case expects a trap, so probe is correct
        # Override expected_allowed to False to make it a trap-expected case
        case["expected"]["allowed"] = False
        case["expected"]["trap_cause"] = 5
        result = _make_result(
            case, status="fail", observed_phase="probe",
            failure_class="wrong_mcause",
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertTrue(qual.eligible, f"expected eligible, got reason={qual.reason}")
        self.assertTrue(qual.semantic_mismatch)


# ---------------------------------------------------------------------------
# 3.  timeout excluded
# ---------------------------------------------------------------------------


class TimeoutExcludedTest(unittest.TestCase):
    def test_timeout_is_not_eligible(self):
        case = _make_case()
        result = _make_result(case, status="timeout", observation_valid=False,
                              stage_verified=False)
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)
        self.assertIn("timeout", qual.reason)


# ---------------------------------------------------------------------------
# 4.  inconclusive excluded
# ---------------------------------------------------------------------------


class InconclusiveExcludedTest(unittest.TestCase):
    def test_inconclusive_is_not_eligible(self):
        case = _make_case()
        result = _make_result(case, status="inconclusive", observation_valid=False)
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)
        self.assertIn("inconclusive", qual.reason.lower())


# ---------------------------------------------------------------------------
# 5.  observation_valid=True but wrong phase excluded
# ---------------------------------------------------------------------------


class WrongPhaseExcludedTest(unittest.TestCase):
    def test_observation_valid_but_wrong_phase_is_excluded(self):
        case = _make_case()
        # observed_event=trap requires observed_phase=probe.
        # Giving observed_phase=completed is a genuine wrong_phase under the
        # actual-event-driven rules.
        result = _make_result(
            case, status="fail", observed_phase="completed",
            observed_event="trap",
            observation_valid=True, stage_verified=False,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)
        self.assertEqual(qual.reason, "wrong_phase")


# ---------------------------------------------------------------------------
# 6.  case.json only → manifest but not execution coverage
# ---------------------------------------------------------------------------


class ManifestOnlyNotExecutionTest(unittest.TestCase):
    def test_case_without_result_increases_manifest_but_not_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})

            cov = coverage_from_run(run_dir)

        # manifest coverage should count the case
        self.assertEqual(cov["total_cases"], 1)
        self.assertGreater(cov["covered_target_bins"], 0)
        # execution coverage must NOT count it (no result file)
        exec_cov = cov.get("execution_coverage")
        self.assertIsNotNone(exec_cov, "coverage.json should contain execution_coverage")
        spike = exec_cov["by_dut"].get("spike")
        self.assertIsNotNone(spike, "execution_coverage.by_dut should contain spike")
        if spike["available"]:
            self.assertEqual(spike["qualification"]["eligible_results"], 0,
                             "case without result must not enter execution coverage")


# ---------------------------------------------------------------------------
# 7.  DUT without Smepmp → Smepmp scenarios excluded from denominator
# ---------------------------------------------------------------------------


class SmepmpDenominatorExcludedTest(unittest.TestCase):
    def test_spike_without_smepmp_excludes_smepmp_bins_from_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case(seed=1, profile="pmp-boundary", include_smepmp=False)
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5

            # Write two run dirs: one without Smepmp, one with Smepmp
            for smepmp, key in ((False, "no_smepmp"), (True, "with_smepmp")):
                rd = run_dir / key
                _write_run_dir(
                    rd,
                    {case["name"]: (case, result)},
                    dut_caps={
                        "schema_version": 3,
                        "duts": {"spike": _make_dut_capability(
                            smepmp_supported=smepmp)},
                    },
                )

            cov_no = coverage_from_run(run_dir / "no_smepmp")
            cov_with = coverage_from_run(run_dir / "with_smepmp")

        spike_no = cov_no["execution_coverage"]["by_dut"]["spike"]
        spike_with = cov_with["execution_coverage"]["by_dut"]["spike"]

        # Smepmp-only bins must be absent from no-Smepmp denominator
        no_smepmp_bins = set(spike_no["semantic"]["covered_bins"]) | set(
            spike_no["semantic"].get("missing_bins", []))
        self.assertFalse(
            any("profile=smepmp-" in item for item in no_smepmp_bins),
            "Smepmp-only bins must not appear when Smepmp is unsupported"
        )
        # With Smepmp must have more target bins
        self.assertGreater(
            len(spike_with["semantic"]["covered_bins"]) +
            spike_with["semantic"]["missing_target_bins"],
            len(spike_no["semantic"]["covered_bins"]) +
            spike_no["semantic"]["missing_target_bins"],
            "with-Smepmp denominator must be larger than without-Smepmp"
        )


# ---------------------------------------------------------------------------
# 8.  Spike vs Rocket different denominators
# ---------------------------------------------------------------------------


class DifferentDutDenominatorsTest(unittest.TestCase):
    def test_spike_and_rocket_have_different_denominators(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result_spike = _make_result(case, dut="spike", status="pass",
                                        observed_phase="probe",
                                        observed_event="trap")
            result_rocket = _make_result(case, dut="rocket-clean", status="pass",
                                         observed_phase="probe",
                                         observed_event="trap")
            (run_dir / "cases" / f"{case['name']}_spike").mkdir(parents=True, exist_ok=True)
            (run_dir / "cases" / f"{case['name']}_rocket").mkdir(parents=True, exist_ok=True)
            (run_dir / "results" / f"{case['name']}_spike").mkdir(parents=True, exist_ok=True)
            (run_dir / "results" / f"{case['name']}_rocket").mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / f"{case['name']}_spike" / "case.json", case)
            write_json(run_dir / "results" / f"{case['name']}_spike" / "result.json", result_spike)
            write_json(run_dir / "cases" / f"{case['name']}_rocket" / "case.json", case)
            write_json(run_dir / "results" / f"{case['name']}_rocket" / "result.json", result_rocket)
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {
                        "spike": _make_dut_capability(dut="spike", smepmp_supported=True),
                        "rocket-clean": _make_dut_capability(dut="rocket-clean", smepmp_supported=False),
                    },
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})

            cov = coverage_from_run(run_dir)

        exec_cov = cov["execution_coverage"]
        spike = exec_cov["by_dut"]["spike"]
        rocket = exec_cov["by_dut"]["rocket-clean"]
        self.assertTrue(spike["available"])
        self.assertTrue(rocket["available"])
        # Denominators must differ because of capability filtering (Smepmp)
        self.assertNotEqual(
            spike["semantic"]["total_target_bins"],
            rocket["semantic"]["total_target_bins"],
            "Spike (Smepmp=true) and Rocket (Smepmp=false) denominators must differ"
        )


# ---------------------------------------------------------------------------
# 9.  missing dut_capabilities.json → unavailable
# ---------------------------------------------------------------------------


class MissingCapabilitiesUnavailableTest(unittest.TestCase):
    def test_missing_capability_file_marks_execution_coverage_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="completed")
            _write_run_dir(run_dir, {case["name"]: (case, result)})  # no dut_capabilities.json

            cov = coverage_from_run(run_dir)

        exec_cov = cov["execution_coverage"]
        # Without capability file, a synthetic "unknown" entry is created
        self.assertIn("by_dut", exec_cov)
        by_dut = exec_cov["by_dut"]
        # All entries should be unavailable
        for dut_name, entry in by_dut.items():
            self.assertFalse(entry.get("available", True),
                             f"missing capabilities → {dut_name} execution coverage unavailable")
            self.assertIn("unavailable_reason", entry)


# ---------------------------------------------------------------------------
# 10.  zero denominator → coverage_rate null
# ---------------------------------------------------------------------------


class ZeroDenominatorNullTest(unittest.TestCase):
    def test_empty_denominator_gives_null_coverage_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            # empty run dir with only capabilities
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability(smepmp_supported=False)},
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})
            (run_dir / "cases").mkdir(parents=True, exist_ok=True)
            (run_dir / "results").mkdir(parents=True, exist_ok=True)

            cov = coverage_from_run(run_dir)

        exec_cov = cov["execution_coverage"]
        spike = exec_cov["by_dut"]["spike"]
        for name in ("semantic", "pairwise", "security_triples", "predicates"):
            section = spike[name]
            if section["total_target_bins"] == 0:
                self.assertIsNone(section["coverage_rate"],
                                  f"{name} coverage_rate must be null when denominator is 0")


# ---------------------------------------------------------------------------
# Extra: excluded statuses
# ---------------------------------------------------------------------------


class ExcludedStatusesTest(unittest.TestCase):
    def test_compile_fail_infra_failure_setup_unsupported_experimental_are_excluded(self):
        case = _make_case()
        excluded = [
            ("compile_fail", "compile_fail"),
            ("infra_failure", "infra_failure"),
            ("setup_unsupported", "setup_unsupported"),
        ]
        for status, reason_keyword in excluded:
            with self.subTest(status=status):
                result = _make_result(case, status=status, observation_valid=False,
                                      oracle_applicability="unsupported")
                qual = qualify_result_for_coverage(case, result)
                self.assertFalse(qual.eligible, f"{status} must be excluded, got {qual.reason}")

    def test_capability_dependent_is_excluded(self):
        case = _make_case()
        result = _make_result(case, status="inconclusive",
                              oracle_applicability="capability_dependent",
                              observation_valid=False)
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)


# ---------------------------------------------------------------------------
# Extra: valid mismatch fail not excluded because status == "fail"
# ---------------------------------------------------------------------------


class ValidMismatchNotExcludedTest(unittest.TestCase):
    def test_valid_oracle_mismatch_fail_is_eligible(self):
        case = _make_case()
        # semantic mismatch: oracle says allowed=True but DUT trapped at probe
        case["expected"]["allowed"] = True
        # When expected_allowed=True, target is "completed". But the DUT trapped
        # at probe — this is a valid mismatch because the oracle can still judge it.
        # In practice, the result status is "fail" with failure_class="unexpected_trap",
        # observation_valid=True, and observed_phase="probe".
        # For a pass-expected case, the target phase is "completed", but the DUT
        # trapped at "probe". The key insight: when status=="fail" and the case
        # expected completion but the DUT trapped, the oracle STILL applied
        # (it judged the trap as wrong), so observation_valid=True.
        # However, the phase check: expected_allowed=True → target="completed",
        # but observed_phase="probe" → wrong_phase. This is BY DESIGN:
        # the DUT didn't reach the target, so it's not execution-qualified coverage.
        # Instead, use a case where expected_allowed=False (trap expected):
        case["expected"]["allowed"] = False
        case["expected"]["trap_cause"] = 5
        result = _make_result(
            case, status="fail", observed_phase="probe",
            failure_class="unexpected_trap", oracle_applicability="valid",
        )
        qual = qualify_result_for_coverage(case, result)
        # Wait — if expected_allowed=False and status=fail with wrong_mcause,
        # the oracle applied (observation_valid=True), DUT trapped at probe,
        # target is "probe" → eligible. This IS a valid mismatch.
        self.assertTrue(qual.eligible,
                        f"valid mismatch fail must be eligible, got reason={qual.reason}")
        self.assertTrue(qual.semantic_mismatch)


# ---------------------------------------------------------------------------
# Extra: multi-DUT without --dut → clear error
# ---------------------------------------------------------------------------


class MultiDutRequiresDutFlagTest(unittest.TestCase):
    def test_multi_dut_schedule_without_dut_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe")
            _write_run_dir(
                run_dir,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {
                        "spike": _make_dut_capability(),
                        "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                    },
                },
            )

            with self.assertRaises(ValueError) as ctx:
                build_schedule(
                    [run_dir],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut=None,  # multi DUT without specifying one
                    max_cases=8,
                    seed=20260628,
                )
            self.assertIn("dut", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# Extra: single-DUT auto-inference
# ---------------------------------------------------------------------------


class SingleDutAutoInferenceTest(unittest.TestCase):
    def test_single_dut_run_dir_auto_infers_dut(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe")
            _write_run_dir(
                run_dir,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )

            schedule = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                max_cases=4,
                seed=20260628,
            )
        self.assertEqual(schedule.get("dut"), "spike")
        self.assertEqual(schedule.get("coverage_basis"), "execution")


# ---------------------------------------------------------------------------
# Extra: wrong_trap_stage with structured mismatch is still valid execution
# ---------------------------------------------------------------------------


class WrongTrapStageValidExecutionTest(unittest.TestCase):
    def test_wrong_trap_stage_is_valid_execution_if_structured(self):
        case = _make_case()
        # wrong_trap_stage: the DUT trapped, observation is valid,
        # and it reached the probe phase — this IS a valid structured execution.
        case["expected"]["allowed"] = False
        case["expected"]["trap_cause"] = 5
        result = _make_result(
            case, status="fail", observed_phase="probe",
            failure_class="wrong_trap_stage",
            observation_valid=True, stage_verified=False,
        )
        qual = qualify_result_for_coverage(case, result)
        # wrong_trap_stage with observation_valid=True and reached probe stage
        # is a valid structured mismatch — must be eligible
        self.assertTrue(qual.eligible,
                        f"wrong_trap_stage with valid observation must be eligible, got {qual.reason}")


# ---------------------------------------------------------------------------
# Fix 1 RED tests: PhaseValid uses observed_event, not expected.allowed
# ---------------------------------------------------------------------------


class UnexpectedTrapEligibleTest(unittest.TestCase):
    """Test A: unexpected_trap must be counted as eligible valid mismatch."""

    def test_unexpected_trap_is_eligible(self):
        case = _make_case()
        # Completion expected (allowed=True) but DUT trapped unexpectedly
        case["expected"]["allowed"] = True
        result = _make_result(
            case, status="fail", observed_phase="probe",
            observed_event="trap",
            failure_class="unexpected_trap",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertTrue(qual.eligible,
                        f"unexpected_trap must be eligible, got reason={qual.reason}")
        self.assertTrue(qual.semantic_mismatch,
                        "unexpected_trap is a valid mismatch")
        self.assertEqual(qual.target_phase, "probe",
                         "observed_event=trap → target_phase must be probe")


class UnexpectedNoTrapEligibleTest(unittest.TestCase):
    """Test B: unexpected_no_trap must be counted as eligible valid mismatch."""

    def test_unexpected_no_trap_is_eligible(self):
        case = _make_case()
        # Trap expected (allowed=False) but DUT completed unexpectedly
        case["expected"]["allowed"] = False
        case["expected"]["trap_cause"] = 5
        result = _make_result(
            case, status="fail", observed_phase="completed",
            observed_event="completion",
            failure_class="unexpected_no_trap",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertTrue(qual.eligible,
                        f"unexpected_no_trap must be eligible, got reason={qual.reason}")
        self.assertTrue(qual.semantic_mismatch,
                        "unexpected_no_trap is a valid mismatch")
        self.assertEqual(qual.target_phase, "completed",
                         "observed_event=completion → target_phase must be completed")


class TrapWrongPhaseExcludedTest(unittest.TestCase):
    """Test C: trap from wrong phase (setup) must be excluded."""

    def test_trap_at_setup_is_wrong_phase(self):
        case = _make_case()
        case["expected"]["allowed"] = True
        result = _make_result(
            case, status="fail", observed_phase="setup",
            observed_event="trap",
            failure_class="unexpected_trap",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)
        self.assertEqual(qual.reason, "wrong_phase")


class CompletionWrongPhaseExcludedTest(unittest.TestCase):
    """Test D: completion from wrong phase (probe) must be excluded."""

    def test_completion_at_probe_is_wrong_phase(self):
        case = _make_case()
        case["expected"]["allowed"] = False
        case["expected"]["trap_cause"] = 5
        result = _make_result(
            case, status="pass", observed_phase="probe",
            observed_event="completion",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible)
        self.assertEqual(qual.reason, "wrong_phase")


class StatefulFinalAllPhasesTest(unittest.TestCase):
    """Test E: stateful_final accepts all four final phase variants."""

    def test_stateful_final_phases_all_accepted(self):
        final_phases = [
            "final",
            "final_sentinel_initial",
            "final_sentinel_modified",
            "final_sentinel_other",
        ]
        for phase in final_phases:
            with self.subTest(phase=phase):
                case = _make_case()
                case["expected"]["stage"] = "stateful_final"
                result = _make_result(
                    case, status="pass", observed_phase=phase,
                    observed_event="completion",
                    oracle_applicability="valid",
                    observation_valid=True,
                    expected_stage_override="stateful_final",
                )
                qual = qualify_result_for_coverage(case, result)
                self.assertTrue(qual.eligible,
                                f"stateful_final {phase} must be eligible, got {qual.reason}")


class UnknownObservedEventExcludedTest(unittest.TestCase):
    """Test F: missing or unknown observed_event must be excluded."""

    def test_unknown_observed_event_is_excluded(self):
        case = _make_case()
        result = _make_result(
            case, status="pass", observed_phase="completed",
            observed_event="unknown_bogus_event",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible,
                         f"unknown observed_event must be excluded, got {qual.reason}")
        self.assertIn(qual.reason,
                      ("missing_structured_observation", "unknown_observation_event"))

    def test_missing_observed_event_is_excluded(self):
        case = _make_case()
        result = _make_result(
            case, status="pass", observed_phase="completed",
            observed_event="",
            oracle_applicability="valid",
            observation_valid=True,
        )
        qual = qualify_result_for_coverage(case, result)
        self.assertFalse(qual.eligible,
                         f"missing observed_event must be excluded, got {qual.reason}")
        self.assertIn(qual.reason,
                      ("missing_structured_observation", "unknown_observation_event"))


# ---------------------------------------------------------------------------
# Fix 2 RED tests: coverage and scheduler use same qualification
# ---------------------------------------------------------------------------


class MissingConcreteObservationExcludedBothSidesTest(unittest.TestCase):
    """Test G: result without concrete observation excluded everywhere."""

    def test_missing_concrete_observation_excluded_by_coverage_and_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(
                case, status="fail", observed_phase="probe",
                observed_event="trap",
                oracle_applicability="valid",
                observation_valid=True,
                failure_class="wrong_mcause",
            )
            # Wipe concrete observation fields to simulate missing structured data.
            # The result reaches probe (correct for trap event) and has valid
            # oracle/status, but lacks parseable observation data.
            result["observed_tohost"] = None
            result["observed_mcause"] = None
            result["observed_mtval"] = None
            _write_run_dir(
                run_dir,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )

            # coverage.py path
            cov = coverage_from_run(run_dir)
            exec_cov = cov["execution_coverage"]
            spike = exec_cov["by_dut"].get("spike", {})
            q = spike.get("qualification", {})
            self.assertEqual(q.get("eligible_results", 0), 0,
                             "no concrete observation → eligible_results must be 0")

            # gap path: must also exclude this result
            gap = coverage_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
                capability=_make_dut_capability(),
            )
            self.assertEqual(len(gap.get("observed_bins", [])), 0,
                             "gap observed_bins must be empty when no result qualifies")

            # scheduler path
            schedule = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                max_cases=4,
                seed=20260628,
            )
            qual = schedule.get("qualification", {})
            self.assertEqual(qual.get("eligible_results", 0), 0,
                             "scheduler: no concrete observation → eligible_results must be 0")


class CoverageAndGapSameEligibleSetTest(unittest.TestCase):
    """Test H: coverage.py and coverage_gap_from_runs use the same eligible cases."""

    @staticmethod
    def _rename_case(case, unique_name):
        import copy
        case = copy.deepcopy(case)
        case["name"] = unique_name
        return case

    def test_coverage_and_gap_have_identical_eligible_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)

            # 1. Legal pass (eligible)
            case1 = self._rename_case(
                _make_case(seed=1, profile="pmp-boundary"), "legal_pass")
            result1 = _make_result(case1, status="pass", observed_phase="probe",
                                   observed_event="trap")
            case1["expected"]["allowed"] = False
            case1["expected"]["trap_cause"] = 5

            # 2. unexpected_trap (eligible mismatch) — different profile
            case2 = self._rename_case(
                _make_case(seed=2, profile="sv39-perm-matrix"), "unexpected_trap")
            case2["expected"]["allowed"] = True
            result2 = _make_result(case2, status="fail", observed_phase="probe",
                                   observed_event="trap",
                                   failure_class="unexpected_trap")

            # 3. timeout (excluded)
            case3 = self._rename_case(
                _make_case(seed=3), "timeout_case")
            result3 = _make_result(case3, status="timeout",
                                   observation_valid=False)

            # 4. missing structured observation (excluded) — different profile
            case4 = self._rename_case(
                _make_case(seed=4, profile="sv39-ptw-pmp-matrix"), "missing_struct")
            case4["expected"]["allowed"] = False
            case4["expected"]["trap_cause"] = 5
            result4 = _make_result(case4, status="fail",
                                   observed_phase="probe",
                                   observed_event="trap",
                                   failure_class="wrong_mcause")
            result4["observed_tohost"] = None
            result4["observed_mcause"] = None
            result4["observed_mtval"] = None

            # 5. wrong phase (excluded)
            case5 = self._rename_case(
                _make_case(seed=5), "wrong_phase_case")
            result5 = _make_result(case5, status="pass",
                                   observed_phase="probe",
                                   observed_event="completion")

            cases_results = {
                case1["name"]: (case1, result1),
                case2["name"]: (case2, result2),
                case3["name"]: (case3, result3),
                case4["name"]: (case4, result4),
                case5["name"]: (case5, result5),
            }
            # Verify all 5 names are unique
            self.assertEqual(len(cases_results), 5)
            self.assertEqual(
                len({case["name"] for case, _ in cases_results.values()}), 5,
            )

            _write_run_dir(
                run_dir, cases_results,
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )

            # coverage.py path
            cov = coverage_from_run(run_dir)
            exec_cov = cov["execution_coverage"]
            spike = exec_cov["by_dut"]["spike"]
            cov_covered = set(spike["semantic"]["covered_bins"])

            # gap path
            gap = coverage_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
                capability=_make_dut_capability(),
            )
            gap_covered = set(gap["covered_bins"])

            self.assertEqual(cov_covered, gap_covered,
                             "coverage and gap must have identical covered bins")


# ---------------------------------------------------------------------------
# Fix 3 RED tests: execution API fail closed
# ---------------------------------------------------------------------------


class DirectGapMissingCapabilityErrorTest(unittest.TestCase):
    """Test I: direct gap APIs must error when capability file is missing."""

    def test_semantic_gap_without_capability_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            _write_run_dir(run_dir, {case["name"]: (case, result)})
            # No dut_capabilities.json written

            with self.assertRaises(ValueError) as ctx:
                coverage_gap_from_runs(
                    [run_dir],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut="spike",
                )
            self.assertIn("capabilit", str(ctx.exception).lower())

    def test_pairwise_gap_without_capability_raises(self):
        from pmpfuzz.semantic_coverage import combination_gap_from_runs
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            _write_run_dir(run_dir, {case["name"]: (case, result)})

            with self.assertRaises(ValueError) as ctx:
                combination_gap_from_runs(
                    [run_dir],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut="spike",
                )
            self.assertIn("capabilit", str(ctx.exception).lower())

    def test_predicate_gap_without_capability_raises(self):
        from pmpfuzz.semantic_coverage import predicate_gap_from_runs
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            _write_run_dir(run_dir, {case["name"]: (case, result)})

            with self.assertRaises(ValueError) as ctx:
                predicate_gap_from_runs(
                    [run_dir],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut="spike",
                )
            self.assertIn("capabilit", str(ctx.exception).lower())


class MultiDutWithoutDutErrorTest(unittest.TestCase):
    """Test J: multi-DUT without --dut must raise error for direct gap."""

    def test_multi_dut_gap_without_dut_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            _write_run_dir(
                run_dir,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {
                        "spike": _make_dut_capability(),
                        "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                    },
                },
            )

            with self.assertRaises(ValueError) as ctx:
                coverage_gap_from_runs(
                    [run_dir],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut=None,
                )
            self.assertIn("dut", str(ctx.exception).lower())


class OneRunMissingCapabilityErrorTest(unittest.TestCase):
    """Test K: when one of two runs is missing capability, must error."""

    def test_two_runs_one_missing_capability_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir1 = Path(tmp) / "run1"
            run_dir2 = Path(tmp) / "run2"
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")

            # run1: has capability
            _write_run_dir(
                run_dir1,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            # run2: no capability file
            _write_run_dir(run_dir2, {case["name"]: (case, result)})

            with self.assertRaises(ValueError) as ctx:
                coverage_gap_from_runs(
                    [run_dir1, run_dir2],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut="spike",
                )
            self.assertIn("capabilit", str(ctx.exception).lower())


class InconsistentCapabilityErrorTest(unittest.TestCase):
    """Test L: two runs with different capability fingerprints must error."""

    def test_inconsistent_capability_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir1 = Path(tmp) / "run1"
            run_dir2 = Path(tmp) / "run2"
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")

            _write_run_dir(
                run_dir1,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability(
                        isa="rv64gc", smepmp_supported=False)},
                },
            )
            _write_run_dir(
                run_dir2,
                {case["name"]: (case, result)},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability(
                        isa="rv64gc_smepmp", smepmp_supported=True)},
                },
            )

            with self.assertRaises(ValueError) as ctx:
                coverage_gap_from_runs(
                    [run_dir1, run_dir2],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut="spike",
                )
            msg = str(ctx.exception).lower()
            self.assertTrue("mismatch" in msg or "fingerprint" in msg
                            or "different" in msg,
                            f"error should mention mismatch/fingerprint, got: {msg}")


class ConsistentCapabilityAggregationTest(unittest.TestCase):
    """Test M: two runs with consistent capability must aggregate correctly."""

    def test_two_consistent_runs_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir1 = Path(tmp) / "run1"
            run_dir2 = Path(tmp) / "run2"

            case1 = _make_case(seed=1, profile="pmp-boundary")
            case1["name"] = "pmp_case"
            case1["expected"]["allowed"] = False
            case1["expected"]["trap_cause"] = 5
            result1 = _make_result(case1, status="pass", observed_phase="probe",
                                   observed_event="trap")

            case2 = _make_case(seed=2, profile="sv39-perm-matrix")
            case2["name"] = "sv39_case"
            case2["expected"]["allowed"] = False
            case2["expected"]["trap_cause"] = 5
            result2 = _make_result(case2, status="pass", observed_phase="probe",
                                   observed_event="trap")

            dut_caps = {
                "schema_version": 3,
                "duts": {"spike": _make_dut_capability()},
            }
            _write_run_dir(run_dir1, {case1["name"]: (case1, result1)},
                           dut_caps=dut_caps)
            _write_run_dir(run_dir2, {case2["name"]: (case2, result2)},
                           dut_caps=dut_caps)

            # Verify aggregation across both runs
            evidence = collect_execution_evidence([run_dir1, run_dir2], dut="spike")
            self.assertEqual(evidence.summary.eligible_results, 2,
                             "both results must be eligible")
            self.assertEqual(evidence.summary.total_results, 2)

            gap = coverage_gap_from_runs(
                [run_dir1, run_dir2],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
            )
            # Verify both profile bins appear in observed bins
            obs_str = " ".join(gap["observed_bins"])
            self.assertIn("profile=pmp-boundary", obs_str,
                          "must contain pmp-boundary bin from run1")
            self.assertIn("profile=sv39-perm-matrix", obs_str,
                          "must contain sv39-perm-matrix bin from run2")


# ---------------------------------------------------------------------------
# Fix 5 RED tests: missing and orphan statistics
# ---------------------------------------------------------------------------


class CaseWithoutResultTest(unittest.TestCase):
    """Test N: case with no result is tracked as missing."""

    def test_case_without_result_has_missing_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            _write_run_dir(
                run_dir,
                {},  # no results
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            # Still need the case file
            (run_dir / "cases" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            evidence = collect_execution_evidence([run_dir], dut="spike")

        self.assertEqual(evidence.summary.total_results, 0)
        self.assertEqual(evidence.summary.eligible_results, 0)
        self.assertEqual(evidence.missing_results, 1)


class ResultWithoutCaseTest(unittest.TestCase):
    """Test O: result without matching case is tracked as orphan."""

    def test_result_without_case_is_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5

            # Write result but NO case file
            (run_dir / "results" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "results" / case["name"] / "result.json", result)
            _write_run_dir(
                run_dir,
                {},  # empty cases_results — but we wrote result manually above
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )

            evidence = collect_execution_evidence([run_dir], dut="spike")

        self.assertEqual(evidence.summary.total_results, 1)
        self.assertEqual(evidence.summary.excluded_results, 1)
        self.assertEqual(evidence.orphan_results, 1)
        self.assertEqual(
            evidence.summary.excluded_by_reason.get("missing_case", 0), 1,
        )


class MultiDutResultsNoCrossContaminationTest(unittest.TestCase):
    """Test P: multi-DUT results don't cross-contaminate per-DUT evidence."""

    def test_multi_dut_results_do_not_cross_contaminate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5

            result_spike = _make_result(case, dut="spike", status="pass",
                                        observed_phase="probe",
                                        observed_event="trap")
            result_rocket = _make_result(case, dut="rocket-clean", status="pass",
                                         observed_phase="probe",
                                         observed_event="trap")

            (run_dir / "cases" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            # Write both results under same case directory
            (run_dir / "results" / f"{case['name']}_spike").mkdir(parents=True, exist_ok=True)
            (run_dir / "results" / f"{case['name']}_rocket").mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "results" / f"{case['name']}_spike" / "result.json", result_spike)
            write_json(run_dir / "results" / f"{case['name']}_rocket" / "result.json", result_rocket)
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {
                        "spike": _make_dut_capability(),
                        "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                    },
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})

            evidence_spike = collect_execution_evidence([run_dir], dut="spike")
            evidence_rocket = collect_execution_evidence([run_dir], dut="rocket-clean")

        # Each DUT only sees its own result
        self.assertEqual(evidence_spike.summary.total_results, 1)
        self.assertEqual(evidence_spike.summary.eligible_results, 1)
        self.assertEqual(evidence_rocket.summary.total_results, 1)
        self.assertEqual(evidence_rocket.summary.eligible_results, 1)
        # Neither should have orphans or missing
        self.assertEqual(evidence_spike.orphan_results, 0)
        self.assertEqual(evidence_spike.missing_results, 0)
        self.assertEqual(evidence_rocket.orphan_results, 0)
        self.assertEqual(evidence_rocket.missing_results, 0)


# ---------------------------------------------------------------------------
# Fix 6 RED tests: no-result denominator
# ---------------------------------------------------------------------------


class NoResultDenominatorPreservedTest(unittest.TestCase):
    """Test Q: capability + no result → C_T preserved, rate=0.0."""

    def test_capability_without_result_preserves_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir,
                {},  # no results
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability(smepmp_supported=False)},
                },
            )

            cov = coverage_from_run(run_dir)

        exec_cov = cov["execution_coverage"]
        spike = exec_cov["by_dut"]["spike"]
        for name in ("semantic", "pairwise", "security_triples", "predicates"):
            section = spike[name]
            self.assertGreater(
                section["total_target_bins"], 0,
                f"{name}: total_target_bins must be > 0 when capability exists"
            )
            self.assertEqual(
                section["covered_target_bins"], 0,
                f"{name}: covered must be 0 with no results"
            )
            self.assertEqual(
                section["missing_target_bins"],
                section["total_target_bins"],
                f"{name}: all target bins must be missing when no results"
            )
            self.assertEqual(
                section["coverage_rate"], 0.0,
                f"{name}: rate must be 0.0, not None, when C_T > 0"
            )


class TrulyZeroDenominatorNullTest(unittest.TestCase):
    """Test R: pmp=False → truly empty C_T → rate=None."""

    def test_pmp_disabled_capability_gives_null_coverage_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            cap = _make_dut_capability(smepmp_supported=False)
            cap["supported_capabilities"]["pmp"] = False
            _write_run_dir(
                run_dir,
                {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": cap},
                },
            )

            cov = coverage_from_run(run_dir)

        exec_cov = cov["execution_coverage"]
        spike = exec_cov["by_dut"]["spike"]
        for name in ("semantic", "pairwise", "security_triples", "predicates"):
            section = spike[name]
            self.assertEqual(
                section["total_target_bins"], 0,
                f"{name}: C_T must be 0 when PMP is unsupported"
            )
            self.assertIsNone(
                section["coverage_rate"],
                f"{name}: rate must be None when C_T is truly empty"
            )


# ---------------------------------------------------------------------------
# Finalization Group 1: execution gap zero denominator → null
# ---------------------------------------------------------------------------


class ExecutionGapZeroDenominatorNullTest(unittest.TestCase):
    """Group 1: execution gap with empty C_T must return rate=None, not 1.0."""

    def _make_pmp_disabled_capability(self):
        cap = _make_dut_capability(smepmp_supported=False)
        cap["supported_capabilities"]["pmp"] = False
        return cap

    def test_semantic_gap_zero_denom_is_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": self._make_pmp_disabled_capability()},
                },
            )
            gap = coverage_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
            )
        self.assertEqual(gap["total_target_bins"], 0)
        self.assertIsNone(gap["coverage_rate"],
                          "execution gap with zero target must have null rate")

    def test_pairwise_gap_zero_denom_is_null(self):
        from pmpfuzz.semantic_coverage import combination_gap_from_runs
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": self._make_pmp_disabled_capability()},
                },
            )
            gap = combination_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                coverage_mode="pairwise",
                dut="spike",
            )
        self.assertEqual(gap["total_target_combo_bins"], 0)
        self.assertIsNone(gap["combo_coverage_rate"],
                          "pairwise gap with zero target must have null rate")

    def test_security_triples_gap_zero_denom_is_null(self):
        from pmpfuzz.semantic_coverage import combination_gap_from_runs
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": self._make_pmp_disabled_capability()},
                },
            )
            gap = combination_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                coverage_mode="security-triples",
                dut="spike",
            )
        self.assertEqual(gap["total_target_combo_bins"], 0)
        self.assertIsNone(gap["combo_coverage_rate"],
                          "security-triples gap with zero target must have null rate")

    def test_predicate_gap_zero_denom_is_null(self):
        from pmpfuzz.semantic_coverage import predicate_gap_from_runs
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": self._make_pmp_disabled_capability()},
                },
            )
            gap = predicate_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
            )
        self.assertEqual(gap["total_target_predicates"], 0)
        self.assertIsNone(gap["predicate_coverage_rate"],
                          "predicate gap with zero target must have null rate")

    def test_manifest_gap_zero_denom_keeps_legacy_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": self._make_pmp_disabled_capability()},
                },
            )
            gap = coverage_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="manifest",
                dut="spike",
            )
        # Manifest mode: zero target may return 1.0 (legacy behaviour)
        # Only check that we don't crash
        self.assertIn("coverage_rate", gap)


# ---------------------------------------------------------------------------
# Finalization Group 2: coverage.py uses collect_execution_evidence
# ---------------------------------------------------------------------------


class CoverageJsonMissingOrphanTest(unittest.TestCase):
    """Group 2 A/B/C: missing and orphan results appear in coverage.json."""

    def test_case_without_result_reports_missing_in_coverage_json(self):
        """A: case has no result → coverage.json shows missing_results=1."""
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            # Write case file without any result
            (run_dir / "cases" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            cov = coverage_from_run(run_dir)

        qual = cov["execution_coverage"]["by_dut"]["spike"]["qualification"]
        self.assertEqual(qual["total_results"], 0)
        self.assertEqual(qual["eligible_results"], 0)
        self.assertEqual(qual["missing_results"], 1,
                         "case without result must be counted as missing")
        section = cov["execution_coverage"]["by_dut"]["spike"]["semantic"]
        self.assertGreater(section["total_target_bins"], 0)
        self.assertEqual(section["coverage_rate"], 0.0)

    def test_orphan_result_appears_in_coverage_json(self):
        """B: result without case → orphan_results=1."""
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            # Write result but NOT the case file
            (run_dir / "results" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "results" / case["name"] / "result.json", result)

            cov = coverage_from_run(run_dir)

        qual = cov["execution_coverage"]["by_dut"]["spike"]["qualification"]
        self.assertEqual(qual["total_results"], 1)
        self.assertEqual(qual["excluded_results"], 1)
        self.assertEqual(qual["orphan_results"], 1,
                         "result without case must be orphan")
        self.assertEqual(qual.get("excluded_by_reason", {}).get("missing_case", 0), 1)

    def test_multi_dut_missing_does_not_cross_contaminate(self):
        """C: Rocket result must not hide Spike missing."""
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result_rocket = _make_result(
                case, dut="rocket-clean", status="pass",
                observed_phase="probe", observed_event="trap",
            )
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {
                        "spike": _make_dut_capability(),
                        "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                    },
                },
            )
            (run_dir / "cases" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            (run_dir / "results" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "results" / case["name"] / "result.json", result_rocket)

            cov = coverage_from_run(run_dir)

        spike_qual = cov["execution_coverage"]["by_dut"]["spike"]["qualification"]
        rocket_qual = cov["execution_coverage"]["by_dut"]["rocket-clean"]["qualification"]
        self.assertEqual(spike_qual["missing_results"], 1,
                         "Spike must report missing when only Rocket has result")
        self.assertEqual(rocket_qual["missing_results"], 0)
        self.assertEqual(spike_qual["total_results"], 0)
        self.assertEqual(rocket_qual["total_results"], 1)


class ReportShowsRealMissingOrphanTest(unittest.TestCase):
    """Group 2 D: report must show real missing/orphan numbers."""

    def test_report_shows_missing_results_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _make_case()
            _write_run_dir(
                run_dir, {},
                dut_caps={
                    "schema_version": 3,
                    "duts": {"spike": _make_dut_capability()},
                },
            )
            (run_dir / "cases" / case["name"]).mkdir(parents=True, exist_ok=True)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            # Generate coverage and verify missing count directly
            cov = coverage_from_run(run_dir)
            qual = cov["execution_coverage"]["by_dut"]["spike"]["qualification"]
            self.assertEqual(qual.get("missing_results", 0), 1,
                             "missing_results must be 1 in coverage.json")

            # Now verify report also shows it
            from pmpfuzz.triage import render_markdown_report
            report = render_markdown_report(run_dir)
            self.assertIn("Missing results: 1", report,
                          "report must show exact missing count")


# ---------------------------------------------------------------------------
# Finalization Group 3: multi-run DUT inference + fingerprint
# ---------------------------------------------------------------------------


class MultiDutAutoInferenceRejectTest(unittest.TestCase):
    """Group 3 E: first run single, second multi → must error without --dut."""

    def test_first_single_second_multi_without_dut_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            run1 = Path(tmp) / "run1"
            run2 = Path(tmp) / "run2"
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            _write_run_dir(run1, {case["name"]: (case, result)},
                           dut_caps={"schema_version": 3,
                                     "duts": {"spike": _make_dut_capability()}})
            _write_run_dir(run2, {case["name"]: (case, result)},
                           dut_caps={"schema_version": 3,
                                     "duts": {
                                         "spike": _make_dut_capability(),
                                         "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                                     }})

            with self.assertRaises(ValueError) as ctx:
                coverage_gap_from_runs(
                    [run1, run2],
                    target=CORE_STATEFUL_TARGET,
                    coverage_basis="execution",
                    dut=None,
                )
            self.assertIn("dut", str(ctx.exception).lower())


class ExplicitDutHandlesMultiDutTest(unittest.TestCase):
    """Group 3 F: explicit --dut works even with multi-DUT second run."""

    def test_explicit_dut_with_multi_dut_second_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run1 = Path(tmp) / "run1"
            run2 = Path(tmp) / "run2"
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            _write_run_dir(run1, {case["name"]: (case, result)},
                           dut_caps={"schema_version": 3,
                                     "duts": {"spike": _make_dut_capability()}})
            _write_run_dir(run2, {case["name"]: (case, result)},
                           dut_caps={"schema_version": 3,
                                     "duts": {
                                         "spike": _make_dut_capability(),
                                         "rocket-clean": _make_dut_capability(dut="rocket-clean"),
                                     }})

            gap = coverage_gap_from_runs(
                [run1, run2],
                target=CORE_STATEFUL_TARGET,
                coverage_basis="execution",
                dut="spike",
            )
            self.assertEqual(len(gap["run_dirs"]), 2)


class GeneratorRunDirsNotExhaustedTest(unittest.TestCase):
    """Group 3 G: generator run_dirs must not be silently exhausted."""

    def test_generator_run_dirs_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            run1 = Path(tmp) / "run1"
            run2 = Path(tmp) / "run2"
            case = _make_case()
            case["expected"]["allowed"] = False
            case["expected"]["trap_cause"] = 5
            result = _make_result(case, status="pass", observed_phase="probe",
                                  observed_event="trap")
            cap = {"schema_version": 3, "duts": {"spike": _make_dut_capability()}}
            _write_run_dir(run1, {case["name"]: (case, result)}, dut_caps=cap)
            _write_run_dir(run2, {case["name"]: (case, result)}, dut_caps=cap)

            run_iter = (path for path in [run1, run2])
            gap = coverage_gap_from_runs(
                run_iter,
                coverage_basis="execution",
                dut="spike",
            )
        self.assertEqual(len(gap["run_dirs"]), 2,
                         "generator must not be exhausted before use")


class FingerprintIgnoresDiagnosticsTest(unittest.TestCase):
    """Group 3 H: fingerprint ignores smepmp diagnostics, path, notes."""

    def test_fingerprint_stable_across_diagnostic_changes(self):
        from pmpfuzz.semantic_coverage import _capability_fingerprint

        cap1 = _make_dut_capability(smepmp_supported=False)
        cap1["path"] = "/some/other/path"
        cap1["notes"] = ["different", "notes"]
        if "smepmp" in cap1:
            cap1["smepmp"]["warl_behavior"] = "modified"
            cap1["smepmp"]["probe_status"] = "changed"

        cap2 = _make_dut_capability(smepmp_supported=False)
        # Different path, notes, diagnostics — same coverage projection
        cap2["path"] = "/completely/different"
        cap2["notes"] = ["other", "stuff"]
        if "smepmp" in cap2:
            cap2["smepmp"]["warl_behavior"] = "other_behavior"
            cap2["smepmp"]["probe_status"] = "other_status"

        self.assertEqual(
            _capability_fingerprint(cap1),
            _capability_fingerprint(cap2),
            "fingerprint must ignore path, notes, and smepmp diagnostics"
        )


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
