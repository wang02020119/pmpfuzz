import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.runner import (
    CampaignResult,
    RunnerConfig,
    _run_indexed_work_with_budget,
    parse_time_budget,
    write_summary,
)


class RunnerTest(unittest.TestCase):
    def test_parse_time_budget_accepts_hours_minutes_and_seconds(self):
        self.assertEqual(parse_time_budget("7h"), 7 * 60 * 60)
        self.assertEqual(parse_time_budget("15m"), 15 * 60)
        self.assertEqual(parse_time_budget("30s"), 30)

    def test_write_summary_records_failures_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            config = RunnerConfig(profile="mixed-smepmp-mmu", count=3, seed=1, jobs=1, time_budget_seconds=60, out=out)
            write_summary(
                config=config,
                results=[
                    CampaignResult(
                        name="case_pass",
                        profile="mixed-smepmp-mmu",
                        status="pass",
                        expected_allowed=True,
                        expected_cause=None,
                        elapsed_seconds=0.1,
                    ),
                    CampaignResult(
                        name="case_fail",
                        profile="mixed-smepmp-mmu",
                        status="fail",
                        expected_allowed=False,
                        expected_cause=5,
                        elapsed_seconds=0.2,
                    ),
                    CampaignResult(
                        name="case_infra",
                        profile="mixed-smepmp-mmu",
                        status="infra_failure",
                        expected_allowed=False,
                        expected_cause=1,
                        elapsed_seconds=0.3,
                    ),
                ],
            )

            summary = json.loads((out / "summary.json").read_text(encoding="ascii"))
            coverage = (out / "coverage.csv").read_text(encoding="ascii")

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["dut"], "spike")
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["infra_failed"], 1)
        self.assertEqual(summary["nonpass"], 2)
        self.assertIn("mixed-smepmp-mmu", coverage)

    def test_time_budget_does_not_submit_all_pending_work_up_front(self):
        calls = []
        clock = {"now": 0.0}

        def run_one(index, item):
            calls.append((index, item))
            clock["now"] = 10.0
            return f"result-{index}"

        results = _run_indexed_work_with_budget(
            [(0, "first"), (1, "second"), (2, "third")],
            run_one,
            max_workers=1,
            start_time=0.0,
            time_budget_seconds=5,
            time_fn=lambda: clock["now"],
        )

        self.assertEqual(results, ["result-0"])
        self.assertEqual(calls, [(0, "first")])


if __name__ == "__main__":
    unittest.main()
