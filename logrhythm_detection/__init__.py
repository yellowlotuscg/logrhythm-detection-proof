"""LogRhythm detection proof: offline, deterministic failed-login window detection.

This package is an offline reference implementation that works only on
explicitly synthetic event data. It is not a genuine LogRhythm AI Engine
rule and it has no vendor integration.
"""

from logrhythm_detection.detector import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    ANALYZER_VERSION,
    AnalysisResult,
    analyze_failed_logins,
)

__version__ = ANALYZER_VERSION
__all__ = [
    "AUTH_FAILURE",
    "AUTH_SUCCESS",
    "ANALYZER_VERSION",
    "AnalysisResult",
    "analyze_failed_logins",
]
