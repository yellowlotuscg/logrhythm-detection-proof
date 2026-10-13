# LogRhythm Detection Proof

A local example for explaining and testing repeated login-failure detection on synthetic events. It needs no LogRhythm account, API token, vendor software, or network connection.

## The problem

A support team has to tell one mistyped password from a run of failures worth investigating. The example groups `auth_failure` events by `identity` (the account) and `source` (where the attempt came from), lists the events behind each finding, and keeps malformed input out of the failure counts.

## Run

Python 3.9 or later. The standard library is enough.

```sh
git clone https://github.com/yellowlotuscg/logrhythm-detection-proof.git
cd logrhythm-detection-proof
python3 -m unittest discover -s tests -v
python3 demo.py
```

Run those commands from the repository root. `run_tests.sh` runs the suite and writes a dated log under `receipts/`.

## Case study

`fixtures/case_study.json` is invented. It is not a customer incident or a LogRhythm export. The account names and addresses are synthetic.

The fixture uses a threshold of 5 failures inside a 300-second window. Those are also the defaults of `analyze_failed_logins`. On this fixture, `python3 demo.py` reports 20 input events, 18 valid events (17 `auth_failure` and 1 `auth_success`), 2 malformed events, 3 `(identity, source)` groups, and 2 detections.

The first detection is `svc.reporting` from `10.24.8.7`: 8 failures, threshold crossed at `2026-09-03T14:05:31Z`, members `lr-0001` through `lr-0008`. The second is `c.meyer` from the same source: 6 failures, threshold crossed at `2026-09-03T14:12:27Z`. Three later failures for `svc.reporting` from `198.51.100.23` stay under the threshold. Each detection includes `member_event_ids` and `fired_at`, the time the count reached the threshold.

Review the source events, who owns the account, lockout state, and any later successful login before escalating. A detection is a reason to investigate. Someone still has to decide whether the account was compromised. This example only reports findings.

## Design and limitations

`logrhythm_detection/detector.py` holds the logic. `analyze_failed_logins` reads one batch of event dicts. A valid event needs `event_id`, a UTC ISO 8601 `timestamp`, `event_type` (`auth_failure` or `auth_success`), `identity`, and `source`.

Failures that share an `identity` and a `source` form one group. Events in a group are ordered by timestamp, and ties keep their input order. A window opens on the first failure of a burst. A later failure stays in that burst when its timestamp is no later than `window_seconds` after the opening failure, so the end boundary counts. A failure after that end closes the burst and opens a new one.

Windows are anchored this way, so a run of failures that crosses from one window into the next can stay under the threshold. A closed burst that reached `threshold` becomes one detection. Further failures inside the same window stay on that detection, so the count can be higher than the threshold. `fired_at` is the timestamp of the failure that reached the count.

Successful logins are included in the summary. They leave failure windows unchanged and they do not add to the failure count.

Duplicate `event_id` values are kept. A replayed event can inflate a detection, so a live feed would need its own deduplication step. Malformed records are returned with their original contents and a reason, and they are left out of the failure counts. Only synthetic data belongs in a public report.

`window_seconds` and `threshold` must be integers greater than or equal to 1. Other values raise `ValueError`.

This repository is a Python illustration of that anchored threshold. It is not an exported AI Engine rule, a LogRhythm parser, or a tested vendor integration. The public docs that informed the window idea are listed in [SOURCES.md](SOURCES.md).

## Tests and license

The suite has 24 tests. They cover window boundaries, separate identities and sources, malformed input, and configuration checks. GitHub Actions runs `python -m unittest discover -s tests -v` on Python 3.12 for pushes and pull requests to `main`. Those checks cover this Python implementation. They are not a vendor acceptance test.

No client data, credentials, or private infrastructure is required.

Licensed under the MIT License. Copyright (c) 2026 Matthew Coggins. See [LICENSE](LICENSE).
