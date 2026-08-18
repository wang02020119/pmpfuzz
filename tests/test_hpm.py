import unittest

from pmpfuzz.hpm import (
    ROCKET_CLEAN_HPM_MANIFEST,
    build_hpm_coverage_universe,
    counter_delta,
    parse_hpm_uart_snapshots,
    rate_bucket_label,
    summarize_hpm_coverage,
)


class HpmCoreTest(unittest.TestCase):
    def test_counter_delta_handles_40bit_wraparound(self):
        width = 40
        before = (1 << width) - 7
        after = 5

        self.assertEqual(counter_delta(before, after, width=width), 12)

    def test_rate_bucket_boundaries_are_finite_and_stable(self):
        self.assertEqual(rate_bucket_label(0.0), "0")
        self.assertEqual(rate_bucket_label(0.1), "0-0.1")
        self.assertEqual(rate_bucket_label(0.1000001), "0.1-1")
        self.assertEqual(rate_bucket_label(1.0), "0.1-1")
        self.assertEqual(rate_bucket_label(1.000001), "1-10")
        self.assertEqual(rate_bucket_label(10.0), "1-10")
        self.assertEqual(rate_bucket_label(10.000001), "10-100")
        self.assertEqual(rate_bucket_label(100.0), "10-100")
        self.assertEqual(rate_bucket_label(100.000001), "gt100")

    def test_uart_snapshot_parser_extracts_before_and_after(self):
        text = (
            "boot banner\n"
            "PMFUZZ_HPM phase=before width=40 minstret=0x10 mcycle=0x20 c3=0x0 c4=0x1 c5=0x2 c6=0x3\n"
            "noise\n"
            "PMFUZZ_HPM phase=after width=40 minstret=0x40 mcycle=0x60 c3=0x4 c4=0x5 c5=0x6 c6=0x7\n"
        )

        snapshots = parse_hpm_uart_snapshots(text)

        self.assertEqual(snapshots["before"]["minstret"], 0x10)
        self.assertEqual(snapshots["before"]["c4"], 0x1)
        self.assertEqual(snapshots["after"]["mcycle"], 0x60)
        self.assertEqual(snapshots["after"]["c6"], 0x7)
        self.assertEqual(snapshots["counter_width"], 40)

    def test_same_bucket_different_raw_values_produce_same_bins(self):
        manifest = ROCKET_CLEAN_HPM_MANIFEST
        first = summarize_hpm_coverage(
            manifest=manifest,
            before={
                "minstret": 1000,
                "mcycle": 2000,
                "c3": 10,
                "c4": 20,
                "c5": 30,
                "c6": 40,
            },
            after={
                "minstret": 2000,
                "mcycle": 2600,
                "c3": 11,
                "c4": 21,
                "c5": 31,
                "c6": 41,
            },
        )
        second = summarize_hpm_coverage(
            manifest=manifest,
            before={
                "minstret": 4000,
                "mcycle": 7000,
                "c3": 1010,
                "c4": 2020,
                "c5": 3030,
                "c6": 4040,
            },
            after={
                "minstret": 5000,
                "mcycle": 7600,
                "c3": 1011,
                "c4": 2021,
                "c5": 3031,
                "c6": 4041,
            },
        )

        self.assertTrue(first["eligible"])
        self.assertEqual(first["observed_bins"], second["observed_bins"])
        self.assertEqual(first["event_metrics"]["exception"]["bucket"], "0.1-1")
        self.assertNotIn("1010", "\n".join(first["observed_bins"]))

    def test_unknown_counter_fails_closed(self):
        manifest = {
            **ROCKET_CLEAN_HPM_MANIFEST,
            "events": list(ROCKET_CLEAN_HPM_MANIFEST["events"])
            + [
                {
                    "name": "unknown-event",
                    "counter": "c9",
                    "event_selector": 0xDEADBEEF,
                    "counter_width": 40,
                    "kind": "rate",
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "unknown-event|c9"):
            summarize_hpm_coverage(
                manifest=manifest,
                before={"minstret": 0, "mcycle": 0, "c3": 0, "c4": 0, "c5": 0, "c6": 0},
                after={"minstret": 10, "mcycle": 20, "c3": 1, "c4": 1, "c5": 1, "c6": 1},
            )

    def test_hpm_universe_bin_set_hash_is_seed_stable_and_bin_sensitive(self):
        first = build_hpm_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
        )
        second = build_hpm_coverage_universe(
            dut="rocket-clean",
            generator_seed=2,
        )
        different = build_hpm_coverage_universe(
            dut="rocket-clean",
            generator_seed=2,
            manifest_override={
                **ROCKET_CLEAN_HPM_MANIFEST,
                "events": ROCKET_CLEAN_HPM_MANIFEST["events"][:-1],
            },
        )

        self.assertEqual(first["bin_set_sha256"], second["bin_set_sha256"])
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertNotEqual(first["bin_set_sha256"], different["bin_set_sha256"])


if __name__ == "__main__":
    unittest.main()
