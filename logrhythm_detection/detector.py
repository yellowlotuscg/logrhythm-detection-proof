"""Deterministic failed-login time window detection (offline reference).

Pure Python standard library implementation for the LogRhythm detection
proof. It accepts a list of synthetic authentication events, validates and
normalizes each one, groups auth_failure events by (identity, source), and
detects bursts that reach a configured failure count inside an anchored
time window.

Window semantics intentionally mirror the LogRhythm documentation for AI
Engine threshold time limits: the duration begins from the time the first
log that meets the criteria appears (see SOURCES.md). A burst is anchored
at its first auth_failure and stays open while each following auth_failure
arrives no later than `window_seconds` after that first event. The boundary
is inclusive. When a later event falls outside the window, the burst closes
and that event starts a new anchored burst.

Nothing here contacts a vendor system, reads credentials, or claims to be
an exported LogRhythm rule.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

ANALYZER_VERSION = "1.0.0"

AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
EVENT_TYPES = (AUTH_FAILURE, AUTH_SUCCESS)
REQUIRED_FIELDS = ("event_id", "timestamp", "event_type", "identity", "source")

_UTC = timezone.utc


def _canonical_iso(value: datetime) -> str:
    """Render a datetime as UTC ISO 8601 with a Z suffix, seconds precision."""
    return value.astimezone(_UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(raw: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse and validate a synthetic event timestamp.

    Returns (datetime, None) on success or (None, reason) on failure.
    """
    if not isinstance(raw, str):
        return None, "timestamp must be a string"
    text = raw.strip()
    if not text:
        return None, "timestamp must be a string"
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, "timestamp is not parseable ISO 8601"
    if parsed.tzinfo is None:
        return None, "timestamp must carry a UTC offset (naive timestamps rejected)"
    if parsed.utcoffset() != timedelta(0):
        return None, "timestamp must be UTC (offset +00:00 required)"
    return parsed, None


def _normalize_event(raw: Any, index: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Validate one raw event and normalize it for analysis.

    Returns (normalized_event, None) or (None, reason). Normalized events
    are plain dicts so the whole analysis result serializes to JSON.
    """
    if not isinstance(raw, dict):
        return None, "event is not an object"
    for field in REQUIRED_FIELDS:
        if field not in raw:
            return None, "missing field: %s" % field
    event_id = raw["event_id"]
    if not isinstance(event_id, str) or not event_id:
        return None, "event_id must be a non-empty string"
    timestamp, timestamp_error = _parse_timestamp(raw["timestamp"])
    if timestamp_error is not None:
        return None, timestamp_error
    assert timestamp is not None  # timestamp_error is None implies success
    event_type = raw["event_type"]
    if event_type not in EVENT_TYPES:
        return None, (
            "unknown event_type %r (expected %s or %s)"
            % (event_type, AUTH_FAILURE, AUTH_SUCCESS)
        )
    identity = raw["identity"]
    if not isinstance(identity, str) or not identity:
        return None, "identity must be a non-empty string"
    source = raw["source"]
    if not isinstance(source, str) or not source:
        return None, "source must be a non-empty string"
    epoch = timestamp.astimezone(_UTC).timestamp()
    return {
        "event_id": event_id,
        "timestamp": _canonical_iso(timestamp),
        "event_type": event_type,
        "identity": identity,
        "source": source,
        "_epoch": epoch,
        "_seq": index,
    }, None


def _make_detection(burst: List[Dict[str, Any]], window_seconds: int, threshold: int) -> Dict[str, Any]:
    """Build a detection record from a closed burst that reached threshold."""
    first = burst[0]
    last = burst[-1]
    start_epoch = first["_epoch"]
    end_epoch = start_epoch + window_seconds
    fired = burst[threshold - 1]
    return {
        "identity": first["identity"],
        "source": first["source"],
        "window_start": first["timestamp"],
        "window_end": _canonical_iso(datetime.fromtimestamp(end_epoch, tz=_UTC)),
        "first_failure": first["timestamp"],
        "last_failure": last["timestamp"],
        "fail_count": len(burst),
        "threshold": threshold,
        "fired_at": fired["timestamp"],
        "member_event_ids": [event["event_id"] for event in burst],
    }


def _detect_for_group(
    failures: List[Dict[str, Any]], window_seconds: int, threshold: int
) -> List[Dict[str, Any]]:
    """Run anchored-window burst detection over one (identity, source) group.

    `failures` must already be sorted by (_epoch, _seq). The window is
    anchored at the first failure of each burst; the boundary is inclusive.
    A burst that reaches `threshold` failures produces exactly one detection
    when the burst closes (a later out-of-window event or end of input).
    """
    detections: List[Dict[str, Any]] = []
    burst: List[Dict[str, Any]] = []
    for event in failures:
        if not burst:
            burst = [event]
            continue
        if event["_epoch"] - burst[0]["_epoch"] <= window_seconds:
            burst.append(event)
            continue
        if len(burst) >= threshold:
            detections.append(_make_detection(burst, window_seconds, threshold))
        burst = [event]
    if burst and len(burst) >= threshold:
        detections.append(_make_detection(burst, window_seconds, threshold))
    return detections


class AnalysisResult(NamedTuple):
    """Result of an offline analysis run.

    detections: list of detection dicts (JSON-serializable)
    malformed: list of {"index", "reason", "event"} dicts, input order
    summary: dict of input and outcome counts
    """

    detections: List[Dict[str, Any]]
    malformed: List[Dict[str, Any]]
    summary: Dict[str, Any]


def analyze_failed_logins(
    events: List[Dict[str, Any]], window_seconds: int = 300, threshold: int = 5
) -> AnalysisResult:
    """Analyze a list of synthetic authentication events.

    Args:
        events: raw event dicts. Each requires event_id, timestamp (ISO 8601
            UTC), event_type (auth_failure or auth_success), identity
            (account), and source (origin host). Anything else is routed to
            the malformed list with a reason; analysis never raises on data.
        window_seconds: anchored window duration in seconds (>= 1).
        threshold: minimum auth_failure count inside one window (>= 1).

    Returns:
        AnalysisResult. Events are sorted chronologically (stable on equal
        timestamps by input position), so output order and content are
        deterministic for the same input, window, and threshold.
    """
    if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds < 1:
        raise ValueError("window_seconds must be an integer >= 1")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be an integer >= 1")

    valid: List[Dict[str, Any]] = []
    malformed: List[Dict[str, Any]] = []
    for index, raw in enumerate(events):
        normalized, error = _normalize_event(raw, index)
        if error is not None:
            malformed.append({"index": index, "reason": error, "event": raw})
        else:
            assert normalized is not None  # error is None implies success
            valid.append(normalized)

    failures = sorted(
        (event for event in valid if event["event_type"] == AUTH_FAILURE),
        key=lambda event: (event["_epoch"], event["_seq"]),
    )
    successes = [event for event in valid if event["event_type"] == AUTH_SUCCESS]

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in failures:
        key = (event["identity"], event["source"])
        groups.setdefault(key, []).append(event)

    detections: List[Dict[str, Any]] = []
    for group_failures in groups.values():
        detections.extend(_detect_for_group(group_failures, window_seconds, threshold))

    summary = {
        "analyzer_version": ANALYZER_VERSION,
        "input_events": len(events),
        "valid_events": len(valid),
        "auth_failure_events": len(failures),
        "auth_success_events": len(successes),
        "malformed_events": len(malformed),
        "group_keys_seen": len(groups),
        "window_seconds": window_seconds,
        "threshold": threshold,
    }
    return AnalysisResult(detections=detections, malformed=malformed, summary=summary)
