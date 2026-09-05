"""Tests for the deterministic failed-login window detector.

Covers grouping by identity/source, inclusive window boundaries,
threshold firing, malformed event routing, deterministic ordering, and
the committed case study fixture.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logrhythm_detection.detector import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    analyze_failed_logins,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "case_study.json"
BASE = datetime(2026, 9, 3, 14, 0, 0, tzinfo=timezone.utc)
WINDOW = 300
THRESHOLD = 5


def iso(seconds_from_base: int) -> str:
    """ISO 8601 UTC string for BASE + offset seconds (whole seconds only)."""
    return (BASE + timedelta(seconds=seconds_from_base)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(
    event_id: str,
    seconds_from_base: int,
    identity: str = "alice",
    source: str = "10.0.0.1",
    event_type: str = AUTH_FAILURE,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": iso(seconds_from_base),
        "event_type": event_type,
        "identity": identity,
        "source": source,
    }


class GroupingTests(unittest.TestCase):
    def test_grouping_by_identity_and_source_separates_keys(self):
        # Five failures for alice from host A and five for bob from host A:
        # same source, different identities. Also five for alice from host B.
        events = []
        for i in range(THRESHOLD):
            events.append(ev("a%d" % i, i * 30, identity="alice", source="10.0.0.1"))
        for i in range(THRESHOLD):
            events.append(ev("b%d" % i, i * 30, identity="bob", source="10.0.0.1"))
        for i in range(THRESHOLD):
            events.append(ev("c%d" % i, i * 30, identity="alice", source="10.0.0.2"))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        keys = sorted((d["identity"], d["source"]) for d in result.detections)
        self.assertEqual(
            keys,
            [("alice", "10.0.0.1"), ("alice", "10.0.0.2"), ("bob", "10.0.0.1")],
        )

    def test_interleaved_keys_independent_windows(self):
        # Alternate failures for two keys at the same seconds; each key must
        # reach its own threshold independently.
        events = []
        for i in range(THRESHOLD):
            events.append(ev("a%d" % i, i * 30, identity="alice", source="10.0.0.1"))
            events.append(ev("b%d" % i, i * 30, identity="bob", source="10.0.0.2"))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 2)
        self.assertEqual(result.detections[0]["identity"], "alice")
        self.assertEqual(result.detections[1]["identity"], "bob")


class WindowBoundaryTests(unittest.TestCase):
    def test_window_boundary_inclusive_at_exact_limit(self):
        # The 5th failure lands exactly at anchor + 300s; inclusive boundary
        # means it still counts and the burst fires.
        events = [ev("e%d" % i, i * 75) for i in range(THRESHOLD)]  # 0,75,150,225,300
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        detection = result.detections[0]
        self.assertEqual(detection["fail_count"], THRESHOLD)
        self.assertEqual(detection["fired_at"], iso(300))
        self.assertEqual(detection["window_end"], iso(300))

    def test_event_past_window_boundary_starts_new_burst(self):
        # Sixth failure at anchor + 301s closes the first burst (fires with 5)
        # and opens a new burst that ends below threshold on its own.
        events = [ev("e%d" % i, i * 75) for i in range(THRESHOLD)]
        events.append(ev("e5", 301))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        self.assertEqual(result.detections[0]["fail_count"], THRESHOLD)
        self.assertEqual(result.detections[0]["member_event_ids"], ["e0", "e1", "e2", "e3", "e4"])

    def test_fires_exactly_at_threshold(self):
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD)]
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        detection = result.detections[0]
        self.assertEqual(detection["fail_count"], THRESHOLD)
        # fired_at is the timestamp of the threshold-crossing member.
        self.assertEqual(detection["fired_at"], iso((THRESHOLD - 1) * 30))

    def test_below_threshold_no_detection(self):
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD - 1)]
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(result.detections, [])
        self.assertEqual(result.summary["auth_failure_events"], THRESHOLD - 1)

    def test_two_separate_bursts_same_key_two_detections(self):
        # Burst of 5 inside 300s, silence, then another burst of 6: the gap
        # (600s > window) re-anchors the window, producing two detections.
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD)]
        for i in range(6):
            events.append(ev("f%d" % i, 700 + i * 30))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 2)
        self.assertEqual(result.detections[0]["fail_count"], THRESHOLD)
        self.assertEqual(result.detections[1]["fail_count"], 6)
        self.assertEqual(result.detections[0]["window_start"], iso(0))
        self.assertEqual(result.detections[1]["window_start"], iso(700))

    def test_detection_fields_shape(self):
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD + 1)]
        detection = analyze_failed_logins(events, WINDOW, THRESHOLD).detections[0]
        self.assertEqual(detection["identity"], "alice")
        self.assertEqual(detection["source"], "10.0.0.1")
        self.assertEqual(detection["window_start"], iso(0))
        self.assertEqual(detection["window_end"], iso(WINDOW))
        self.assertEqual(detection["first_failure"], iso(0))
        self.assertEqual(detection["last_failure"], iso(THRESHOLD * 30))
        self.assertEqual(detection["member_event_ids"], ["e0", "e1", "e2", "e3", "e4", "e5"])
        self.assertEqual(len(detection["member_event_ids"]), detection["fail_count"])


class OrderingTests(unittest.TestCase):
    def test_unsorted_input_deterministic_output(self):
        chronological = [ev("e%d" % i, i * 30) for i in range(THRESHOLD)]
        shuffled = [chronological[3], chronological[0], chronological[4],
                    chronological[2], chronological[1]]
        base = analyze_failed_logins(chronological, WINDOW, THRESHOLD)
        scrambled = analyze_failed_logins(shuffled, WINDOW, THRESHOLD)
        self.assertEqual(base.detections, scrambled.detections)
        detection = scrambled.detections[0]
        self.assertEqual(detection["member_event_ids"], ["e0", "e1", "e2", "e3", "e4"])

    def test_duplicate_timestamps_stable_by_input_order(self):
        # All five failures share one timestamp; the sort must be stable on
        # input position and the burst must still fire exactly once.
        events = [ev("e%d" % i, 0) for i in range(THRESHOLD)]
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        detection = result.detections[0]
        self.assertEqual(detection["fail_count"], THRESHOLD)
        self.assertEqual(detection["fired_at"], iso(0))
        self.assertEqual(detection["member_event_ids"], ["e0", "e1", "e2", "e3", "e4"])

    def test_auth_success_never_counts_toward_threshold(self):
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD - 1)]
        events.append(ev("s1", 120, event_type=AUTH_SUCCESS))
        events.append(ev("s2", 121, event_type=AUTH_SUCCESS))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(result.detections, [])
        self.assertEqual(result.summary["auth_success_events"], 2)
        # And successes in the middle of a real burst do not reset it.
        events = [ev("e%d" % i, i * 30) for i in range(THRESHOLD)]
        events.append(ev("s3", 120, event_type=AUTH_SUCCESS))
        result = analyze_failed_logins(events, WINDOW, THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        self.assertEqual(result.detections[0]["fail_count"], THRESHOLD)


class MalformedEventTests(unittest.TestCase):
    def test_missing_required_fields_each_reason(self):
        cases = [
            ("event_id", "missing field: event_id"),
            ("timestamp", "missing field: timestamp"),
            ("event_type", "missing field: event_type"),
            ("identity", "missing field: identity"),
            ("source", "missing field: source"),
        ]
        for field, expected_reason in cases:
            with self.subTest(missing=field):
                event = ev("e0", 0)
                del event[field]
                result = analyze_failed_logins([event], WINDOW, THRESHOLD)
                self.assertEqual(result.summary["malformed_events"], 1)
                self.assertEqual(result.malformed[0]["reason"], expected_reason)
                self.assertEqual(result.detections, [])

    def test_type_and_value_variants_routed(self):
        cases = [
            ({"event_id": "", "timestamp": iso(0), "event_type": AUTH_FAILURE,
              "identity": "alice", "source": "10.0.0.1"},
             "event_id must be a non-empty string"),
            ({"event_id": "e0", "timestamp": 12345, "event_type": AUTH_FAILURE,
              "identity": "alice", "source": "10.0.0.1"},
             "timestamp must be a string"),
            ({"event_id": "e0", "timestamp": "not-a-timestamp", "event_type": AUTH_FAILURE,
              "identity": "alice", "source": "10.0.0.1"},
             "timestamp is not parseable ISO 8601"),
            ({"event_id": "e0", "timestamp": "2026-09-03T14:03:12", "event_type": AUTH_FAILURE,
              "identity": "alice", "source": "10.0.0.1"},
             "timestamp must carry a UTC offset (naive timestamps rejected)"),
            ({"event_id": "e0", "timestamp": "2026-09-03T14:03:12+02:00", "event_type": AUTH_FAILURE,
              "identity": "alice", "source": "10.0.0.1"},
             "timestamp must be UTC (offset +00:00 required)"),
            ({"event_id": "e0", "timestamp": iso(0), "event_type": "auth_unknown",
              "identity": "alice", "source": "10.0.0.1"},
             "unknown event_type 'auth_unknown' (expected auth_failure or auth_success)"),
            ({"event_id": "e0", "timestamp": iso(0), "event_type": AUTH_FAILURE,
              "identity": "", "source": "10.0.0.1"},
             "identity must be a non-empty string"),
            ({"event_id": "e0", "timestamp": iso(0), "event_type": AUTH_FAILURE,
              "identity": 7, "source": "10.0.0.1"},
             "identity must be a non-empty string"),
            ({"event_id": "e0", "timestamp": iso(0), "event_type": AUTH_FAILURE,
              "identity": "alice", "source": ""},
             "source must be a non-empty string"),
            ({"event_id": "e0", "timestamp": iso(0), "event_type": AUTH_FAILURE,
              "identity": "alice", "source": None},
             "source must be a non-empty string"),
        ]
        for event, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                result = analyze_failed_logins([event], WINDOW, THRESHOLD)
                self.assertEqual(result.malformed[0]["reason"], expected_reason)
                self.assertEqual(result.detections, [])

    def test_non_dict_event_rejected(self):
        result = analyze_failed_logins(["just a string"], WINDOW, THRESHOLD)
        self.assertEqual(result.malformed[0]["reason"], "event is not an object")
        self.assertEqual(result.malformed[0]["index"], 0)

    def test_malformed_events_do_not_block_valid_events(self):
        good = [ev("e%d" % i, i * 30) for i in range(THRESHOLD)]
        bad = {"event_id": "e9", "timestamp": iso(0), "event_type": AUTH_FAILURE}
        result = analyze_failed_logins([bad] + good, WINDOW, THRESHOLD)
        self.assertEqual(result.summary["malformed_events"], 1)
        self.assertEqual(result.summary["valid_events"], THRESHOLD)
        self.assertEqual(len(result.detections), 1)
        self.assertEqual(result.malformed[0]["index"], 0)

    def test_empty_stream(self):
        result = analyze_failed_logins([], WINDOW, THRESHOLD)
        self.assertEqual(result.detections, [])
        self.assertEqual(result.malformed, [])
        self.assertEqual(result.summary["input_events"], 0)
        self.assertEqual(result.summary["group_keys_seen"], 0)


class ConfigurationTests(unittest.TestCase):
    def test_invalid_configuration_raises_value_error(self):
        event = ev("e0", 0)
        for window in (0, -5, True, 1.5, "300"):
            with self.subTest(window=window):
                with self.assertRaises(ValueError):
                    analyze_failed_logins([event], window_seconds=window, threshold=5)
        for threshold in (0, -5, True, 2.5, "5"):
            with self.subTest(threshold=threshold):
                with self.assertRaises(ValueError):
                    analyze_failed_logins([event], window_seconds=300, threshold=threshold)


class CaseStudyFixtureTests(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE_PATH, "r", encoding="utf-8") as handle:
            self.fixture = json.load(handle)
        self.scenario = self.fixture["scenario"]
        self.result = analyze_failed_logins(
            self.fixture["events"],
            window_seconds=self.scenario["window_seconds"],
            threshold=self.scenario["threshold"],
        )

    def test_fixture_is_labeled_synthetic(self):
        self.assertTrue(self.scenario["synthetic"])
        self.assertIn("Synthetic", self.fixture["schema_note"])

    def test_case_study_produces_exactly_two_detections(self):
        self.assertEqual(len(self.result.detections), 2)

    def test_detection_one_svc_reporting_from_internal_source(self):
        detection = self.result.detections[0]
        self.assertEqual(detection["identity"], "svc.reporting")
        self.assertEqual(detection["source"], "10.24.8.7")
        self.assertEqual(detection["fail_count"], 8)
        self.assertEqual(detection["threshold"], 5)
        self.assertEqual(detection["window_start"], "2026-09-03T14:03:12Z")
        self.assertEqual(detection["window_end"], "2026-09-03T14:08:12Z")
        self.assertEqual(detection["fired_at"], "2026-09-03T14:05:31Z")
        self.assertEqual(detection["member_event_ids"][0], "lr-0001")
        self.assertEqual(detection["member_event_ids"][-1], "lr-0008")

    def test_detection_two_c_meyer_grouped_separately(self):
        detection = self.result.detections[1]
        self.assertEqual(detection["identity"], "c.meyer")
        self.assertEqual(detection["source"], "10.24.8.7")
        self.assertEqual(detection["fail_count"], 6)
        self.assertEqual(detection["fired_at"], "2026-09-03T14:12:27Z")

    def test_spread_out_failures_do_not_fire(self):
        # svc.reporting from 198.51.100.23 at 14:20, 14:27, 14:35 must not
        # appear in any detection.
        member_ids = [event_id for d in self.result.detections
                      for event_id in d["member_event_ids"]]
        self.assertNotIn("lr-0016", member_ids)
        self.assertNotIn("lr-0017", member_ids)
        self.assertNotIn("lr-0018", member_ids)

    def test_malformed_events_recorded_with_reasons(self):
        reasons = [item["reason"] for item in self.result.malformed]
        self.assertEqual(len(self.result.malformed), 2)
        self.assertEqual(
            reasons,
            [
                "missing field: identity",
                "unknown event_type 'auth_unknown' (expected auth_failure or auth_success)",
            ],
        )

    def test_case_study_summary_counts(self):
        summary = self.result.summary
        self.assertEqual(summary["input_events"], 20)
        self.assertEqual(summary["valid_events"], 18)
        self.assertEqual(summary["auth_failure_events"], 17)
        self.assertEqual(summary["auth_success_events"], 1)
        self.assertEqual(summary["malformed_events"], 2)
        self.assertEqual(summary["group_keys_seen"], 3)


if __name__ == "__main__":
    unittest.main()
