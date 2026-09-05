# LogRhythm Detection Proof

A local, synthetic investigation example for explaining and testing repeated-login-failure detection. No LogRhythm account, API token, vendor software or network connection is needed.

## The business problem

A busy support team needs to distinguish an isolated mistyped password from repeated failures worth investigating. This example groups failures by account and source, explains which events triggered a finding, and separates malformed input rather than quietly counting it.

## Run

Requires Python 3.9 or later, standard library only.

```sh
python3 -m unittest discover -s tests -v
python3 demo.py
```

## Demonstration case study

The included fixture is invented, not a customer incident or a captured LogRhythm export. Its account names and network addresses are synthetic.

Local execution produced 20 input events, 18 valid events, 2 malformed events and 2 detections. The default threshold is five failures within a 300-second anchored window. Each detection includes source event IDs and the time the threshold was crossed. Tests cover window boundaries, separated identities and sources, malformed input and configuration validation.

An analyst should review the source events, account ownership, lockout state and subsequent successful logins before escalating. A detection is a reason to investigate, not proof of compromise. This example takes no account-blocking or remediation actions.

## Design and limitations

- `logrhythm_detection/detector.py` contains the deterministic logic.
- Windows begin at the first failure in a group and include the ending boundary. This is not an overlapping sliding-window algorithm; some bursts spanning anchored windows can be missed.
- Successful logins are counted in the summary but do not reset failure windows.
- Input is processed as a batch, not as a streaming event service.
- Duplicate event IDs are not deduplicated. Replayed events can inflate a detection; an ingestion adapter needs a deduplication policy.
- Malformed records are returned with their raw contents. Only synthetic data belongs in public reports; real event data would require redaction and access controls.
- This is not an exported AIE rule, LogRhythm parser or tested vendor integration. See [official research sources](SOURCES.md) for the concepts that informed it. Vendor deployment and exact rule semantics are outside this public example.

## Verification and privacy

The local suite passed 24 tests. GitHub Actions runs the suite separately. These checks validate this Python implementation, not vendor acceptance or production security. No client data, credentials or private infrastructure is required. No license grant is implied by public visibility.
