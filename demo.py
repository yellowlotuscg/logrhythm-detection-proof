#!/usr/bin/env python3
"""Deterministic investigation demo over the synthetic case study fixture.

Output is fully deterministic: the fixture carries fixed timestamps and the
analysis is pure. No clock, network, or random source is consulted.
"""

import json
import os

from logrhythm_detection.detector import analyze_failed_logins

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "case_study.json")


def main() -> None:
    with open(FIXTURE, "r", encoding="utf-8") as handle:
        fixture = json.load(handle)

    scenario = fixture["scenario"]
    events = fixture["events"]
    result = analyze_failed_logins(
        events,
        window_seconds=scenario["window_seconds"],
        threshold=scenario["threshold"],
    )
    summary = result.summary

    print("LogRhythm detection proof: offline investigation demo")
    print("=" * 62)
    print("Scenario: %s" % scenario["title"])
    print("Fixture:  %s" % os.path.basename(FIXTURE))
    print("Synthetic: %s (schema_note in fixture)" % ("yes" if scenario["synthetic"] else "no"))
    print("Window:   %s seconds (anchored at first auth_failure)" % summary["window_seconds"])
    print("Threshold: %s auth_failure events per window" % summary["threshold"])
    print("=" * 62)
    print("Input summary")
    print("  input events       : %s" % summary["input_events"])
    print("  valid events       : %s" % summary["valid_events"])
    print("  auth_failure events: %s" % summary["auth_failure_events"])
    print("  auth_success events: %s" % summary["auth_success_events"])
    print("  malformed events   : %s" % summary["malformed_events"])
    print("  group keys seen    : %s (identity, source)" % summary["group_keys_seen"])
    print("  detections         : %s" % len(result.detections))
    print()

    if not result.detections:
        print("No detections. No identity/source group reached the threshold")
        print("inside one anchored window.")
        print()

    for number, detection in enumerate(result.detections, start=1):
        print("Detection %d" % number)
        print("  identity   : %s" % detection["identity"])
        print("  source     : %s" % detection["source"])
        print("  window     : %s to %s (%s seconds)" % (
            detection["window_start"],
            detection["window_end"],
            summary["window_seconds"],
        ))
        print("  failures   : %s (threshold %s, crossed at %s)" % (
            detection["fail_count"],
            detection["threshold"],
            detection["fired_at"],
        ))
        print("  first/last : %s to %s" % (
            detection["first_failure"],
            detection["last_failure"],
        ))
        print("  members    : %s" % ", ".join(detection["member_event_ids"]))
        print("  investigate: identity %r recorded %s auth failures from source %r" % (
            detection["identity"],
            detection["fail_count"],
            detection["source"],
        ))
        print("               between %s and %s. Confirm the source host was" % (
            detection["first_failure"],
            detection["last_failure"],
        ))
        print("               not compromised, check account lockout state, and")
        print("               review any later successful login for this identity.")
        print()

    if result.malformed:
        print("Malformed events (validation failures, excluded from analysis)")
        for item in result.malformed:
            print("  [%s] %s" % (item["index"], item["reason"]))
        print()


if __name__ == "__main__":
    main()
