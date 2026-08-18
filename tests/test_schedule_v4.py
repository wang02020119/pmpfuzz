import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_hash, scenario_to_spec
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4


class ScheduleV4Test(unittest.TestCase):
    def test_candidate_admitted_is_atomic_seen_and_pending_record(self):
        scenario = ScenarioGenerator(seed=11, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_admitted",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=1,
                parent_hash=None,
                mutation_operator="root",
            )

            state = recover_schedule_v4(path)

        self.assertEqual(state.next_event_seq, 2)
        self.assertEqual(state.pending_hashes, [spec_hash])
        self.assertIn(spec_hash, state.seen_hashes)
        self.assertIn(spec_hash, state.candidate_records)

    def test_candidate_rejected_replays_generation_counters_without_queueing(self):
        scenario = ScenarioGenerator(seed=12, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_rejected",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=4,
                parent_hash="parent-hash",
                mutation_operator="toggle-stateful-sequence",
                mutation_seed=9,
                mutation_depth=2,
                rejection_reason="warmup requires initially allowed probe",
            )

            state = recover_schedule_v4(path)

        self.assertEqual(state.next_generation_seq, 4)
        self.assertEqual(state.next_mutation_attempt, 10)
        self.assertEqual(state.parent_selection_counts["parent-hash"], 1)
        self.assertEqual(state.pending_hashes, [])
        self.assertNotIn(spec_hash, state.seen_hashes)

    def test_append_and_recover_state(self):
        scenario = ScenarioGenerator(seed=1, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_generated",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=1,
                parent_hash=None,
                mutation_operator="root",
            )
            writer.append("candidate_queued", scenario_hash=spec_hash)
            writer.append("execution_completed", scenario_hash=spec_hash, status="pass", eligible=True)
            writer.append(
                "coverage_recorded",
                scenario_hash=spec_hash,
                new_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
            )
            writer.append("corpus_promoted", scenario_hash=spec_hash)

            state = recover_schedule_v4(path)

        self.assertEqual(state.next_event_seq, 6)
        self.assertIn(spec_hash, state.seen_hashes)
        self.assertIn(spec_hash, state.completed_hashes)
        self.assertEqual(state.pending_hashes, [])
        self.assertIn(spec_hash, state.active_corpus_hashes)
        self.assertEqual(state.coverage_state["semantic"], {"sem:0"})
        self.assertIn(spec_hash, state.candidate_records)
        self.assertEqual(state.completed_cases, 1)
        self.assertEqual(state.eligible_cases, 1)

    def test_recover_ignores_truncated_tail_line(self):
        scenario = ScenarioGenerator(seed=2, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_generated",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=1,
                parent_hash=None,
                mutation_operator="root",
            )
            with path.open("ab") as fh:
                fh.write(b'{"schema_version":4,"event_seq":2,"event":"candidate_queued"')

            state = recover_schedule_v4(path)

        self.assertEqual(state.next_event_seq, 2)
        self.assertIn(spec_hash, state.seen_hashes)

    def test_writer_repairs_truncated_tail_before_append(self):
        scenario = ScenarioGenerator(seed=4, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "candidate_generated",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=1,
                parent_hash=None,
                mutation_operator="root",
            )
            with path.open("ab") as fh:
                fh.write(b'{"schema_version":4,"event_seq":2,"event":"candidate_queued"')

            repaired = ScheduleV4Writer(path)
            repaired.append("candidate_queued", scenario_hash=spec_hash)

            lines = [line for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
            state = recover_schedule_v4(path)

        self.assertEqual(len(lines), 2)
        second = json.loads(lines[1])
        self.assertEqual(second["event"], "candidate_queued")
        self.assertEqual(state.next_event_seq, 3)

    def test_reopen_preserves_valid_records_after_blank_lines(self):
        scenario = ScenarioGenerator(seed=5, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)
        generated = (
            json.dumps(
                {
                    "schema_version": 4,
                    "event_seq": 1,
                    "event": "candidate_generated",
                    "scenario_hash": spec_hash,
                    "scenario_spec": spec,
                    "generation_seq": 1,
                    "parent_hash": None,
                    "mutation_operator": "root",
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        queued = (
            json.dumps(
                {
                    "schema_version": 4,
                    "event_seq": 2,
                    "event": "candidate_queued",
                    "scenario_hash": spec_hash,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            path.write_bytes(generated + b"\n" + queued)

            writer = ScheduleV4Writer(path)
            writer.append("checkpoint", round_idx=0, pending_count=1, corpus_count=0, completed_cases=0, eligible_cases=0)
            state = recover_schedule_v4(path)
            events = [json.loads(line) for line in path.read_text(encoding="ascii").splitlines() if line.strip()]

        self.assertEqual(state.pending_hashes, [spec_hash])
        self.assertEqual([event["event"] for event in events[:2]], ["candidate_generated", "candidate_queued"])

    def test_reopen_inserts_newline_after_complete_tail_record(self):
        scenario = ScenarioGenerator(seed=6, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec_hash = scenario_hash(spec)
        generated = json.dumps(
            {
                "schema_version": 4,
                "event_seq": 1,
                "event": "candidate_generated",
                "scenario_hash": spec_hash,
                "scenario_spec": spec,
                "generation_seq": 1,
                "parent_hash": None,
                "mutation_operator": "root",
            },
            sort_keys=True,
        ).encode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            path.write_bytes(generated)

            writer = ScheduleV4Writer(path)
            writer.append("candidate_queued", scenario_hash=spec_hash)

            lines = [line for line in path.read_text(encoding="ascii").splitlines() if line.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["event"], "candidate_generated")
        self.assertEqual(json.loads(lines[1])["event"], "candidate_queued")

    def test_recover_rejects_non_contiguous_event_seq(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            path.write_text(
                "\n".join(
                    [
                        json.dumps({"schema_version": 4, "event_seq": 1, "event": "checkpoint"}),
                        json.dumps({"schema_version": 4, "event_seq": 3, "event": "checkpoint"}),
                    ]
                )
                + "\n",
                encoding="ascii",
            )

            with self.assertRaises(ValueError):
                recover_schedule_v4(path)

    def test_append_rejects_invalid_transition_without_persisting_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)

            with self.assertRaises(ValueError):
                writer.append("candidate_queued", scenario_hash="deadbeef")

            self.assertFalse(path.exists())

    def test_recover_rejects_spec_hash_mismatch(self):
        scenario = ScenarioGenerator(seed=3, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 4,
                        "event_seq": 1,
                        "event": "candidate_generated",
                        "scenario_hash": "0" * 64,
                        "scenario_spec": spec,
                        "generation_seq": 1,
                        "parent_hash": None,
                        "mutation_operator": "root",
                    }
                )
                + "\n",
                encoding="ascii",
            )

            with self.assertRaises(ValueError):
                recover_schedule_v4(path)


if __name__ == "__main__":
    unittest.main()
