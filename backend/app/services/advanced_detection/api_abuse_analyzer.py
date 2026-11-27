"""
API abuse and enumeration-review analyzers — MW2 (advisory only).

This module reads only the aggregated ``ApiAbuseSnapshot``; it does not read
traffic, call detectors, write a database or emit enforcement actions.
Authentication failures are reviewed by ``credential_abuse_analyzer`` from
aggregate counts only and are not reprocessed here.

WINDOW DEFINITION
  The window is supplied by the caller via ``ApiAbuseSnapshot.window``.
  The ``window_request_threshold`` field is an explicitly supplied per-window
  request count; it is compared with ``peak_requests_per_window`` to express a
  deterministic volume deviation. No clock value or fitted distribution is used.

THRESHOLDS (advisory review only)
  api_abuse (cap 15)
    peak_requests_per_window >= window_request_threshold ........ 3.0
    burst_count >= 3 ........................................... 2.5
    4xx_count >= 10 or 5xx_count >= 5 ........................... 3.0
    distinct_method_count >= 4 or rare_method_count >= 1 ........ 2.0
    scraping_path_repeat_count >= 8 ............................. 2.0
    request_count >= 50 with distinct_path_count >= 20 .......... 1.5

  enumeration_review (cap 5)
    enumeration_path_count >= 3 ................................. 2.0
    sequential_object_count >= 5 ................................ 2.0
    distinct_path_count >= 20 with request_count >= 50 .......... 1.0

A single weak signal never produces a suspicious conclusion. Every result
contains a neutral explanation and deduplication key.
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    ApiAbuseSnapshot,
)
from app.schemas.unified_risk_assessment import ThreatCategory
from app.services.advanced_detection.common_signal_contract import (
    active_result,
    inactive_result,
)
from app.services.advanced_detection.evidence_catalog import (
    bounded_refs,
    dedupe_key,
)

SOURCE_MODULE = "app.services.advanced_detection.api_abuse_analyzer"
API_FUNCTION = "analyze_api_abuse"
ENUMERATION_FUNCTION = "analyze_enumeration_review"

BURST_MIN_COUNT = 3
ERROR_4XX_MIN = 10
ERROR_5XX_MIN = 5
METHOD_DIVERSITY_MIN = 4
RARE_METHOD_MIN = 1
SCRAPING_REPEAT_MIN = 8
HIGH_VOLUME_REQUESTS = 50
HIGH_PATH_DIVERSITY = 20
ENUMERATION_PATH_MIN = 3
SEQUENTIAL_OBJECT_MIN = 5

API_POINTS_VOLUME_DEVIATION = 3.0
API_POINTS_BURST = 2.5
API_POINTS_ERROR_BURST = 3.0
API_POINTS_METHOD_SHAPE = 2.0
API_POINTS_SCRAPING_REPEAT = 2.0
API_POINTS_BROAD_HIGH_VOLUME = 1.5
ENUMERATION_POINTS_PATH_SWEEP = 2.0
ENUMERATION_POINTS_SEQUENTIAL_OBJECTS = 2.0
ENUMERATION_POINTS_BROAD_PATHS = 1.0


def _shared_evidence(snapshot: ApiAbuseSnapshot) -> list[str]:
    return bounded_refs(snapshot.evidence_refs)


def _coverage_note(snapshot: ApiAbuseSnapshot, indicator_count: int) -> str | None:
    notes: list[str] = []
    if snapshot.limits.truncated:
        notes.append("Aggregated API snapshot was truncated; coverage is reduced.")
    if indicator_count < 2:
        notes.append(
            "Fewer than two indicators were present; no suspicious intent is inferred."
        )
    return " ".join(notes) or None


def analyze_api_abuse(snapshot: ApiAbuseSnapshot | None):
    """Return a bounded API-abuse review signal from aggregated indicators."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.API_ABUSE,
            detection_name="API abuse indicator review",
            threat_category=ThreatCategory.TRAFFIC_ANOMALY,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=API_FUNCTION,
        )

    reasons: list[AdvancedReason] = []
    indicators: list[str] = []
    raw_points = 0.0

    if snapshot.peak_requests_per_window >= snapshot.window_request_threshold:
        indicators.append("WINDOW_VOLUME_DEVIATION")
        raw_points += API_POINTS_VOLUME_DEVIATION
        reasons.append(
            AdvancedReason(
                code="WINDOW_VOLUME_DEVIATION",
                message=(
                    f"Peak window requests ({snapshot.peak_requests_per_window}) reached the "
                    f"supplied threshold ({snapshot.window_request_threshold}); this is a "
                    "review indicator, not a calibrated anomaly probability."
                ),
                evidence_count=snapshot.peak_requests_per_window,
                score_contribution=API_POINTS_VOLUME_DEVIATION,
            )
        )

    if snapshot.burst_count >= BURST_MIN_COUNT:
        indicators.append("REPEATED_REQUEST_BURSTS")
        raw_points += API_POINTS_BURST
        reasons.append(
            AdvancedReason(
                code="REPEATED_REQUEST_BURSTS",
                message=(
                    f"{snapshot.burst_count} burst indicator(s) were supplied; bursts can "
                    "also result from retries or scheduled clients."
                ),
                evidence_count=snapshot.burst_count,
                score_contribution=API_POINTS_BURST,
            )
        )

    if (
        snapshot.error_4xx_count >= ERROR_4XX_MIN
        or snapshot.error_5xx_count >= ERROR_5XX_MIN
    ):
        indicators.append("HTTP_ERROR_BURST")
        raw_points += API_POINTS_ERROR_BURST
        reasons.append(
            AdvancedReason(
                code="HTTP_ERROR_BURST",
                message=(
                    "Aggregated 4xx/5xx counts reached review thresholds; upstream "
                    "failures and client defects remain possible explanations."
                ),
                evidence_count=snapshot.error_4xx_count + snapshot.error_5xx_count,
                score_contribution=API_POINTS_ERROR_BURST,
            )
        )

    if (
        snapshot.distinct_method_count >= METHOD_DIVERSITY_MIN
        or snapshot.rare_method_count >= RARE_METHOD_MIN
    ):
        indicators.append("UNUSUAL_METHOD_DISTRIBUTION")
        raw_points += API_POINTS_METHOD_SHAPE
        reasons.append(
            AdvancedReason(
                code="UNUSUAL_METHOD_DISTRIBUTION",
                message=(
                    "Method diversity or rare methods were supplied as review context; "
                    "this does not establish malicious intent."
                ),
                evidence_count=snapshot.distinct_method_count
                + snapshot.rare_method_count,
                score_contribution=API_POINTS_METHOD_SHAPE,
            )
        )

    if snapshot.scraping_path_repeat_count >= SCRAPING_REPEAT_MIN:
        indicators.append("REPEATED_PATH_READ_PATTERN")
        raw_points += API_POINTS_SCRAPING_REPEAT
        reasons.append(
            AdvancedReason(
                code="REPEATED_PATH_READ_PATTERN",
                message=(
                    "Repeated path reads were supplied as a scraping-like review shape; "
                    "no body, header or user identity was inspected."
                ),
                evidence_count=snapshot.scraping_path_repeat_count,
                score_contribution=API_POINTS_SCRAPING_REPEAT,
            )
        )

    if (
        snapshot.request_count >= HIGH_VOLUME_REQUESTS
        and snapshot.distinct_path_count >= HIGH_PATH_DIVERSITY
    ):
        indicators.append("BROAD_HIGH_VOLUME_ACCESS")
        raw_points += API_POINTS_BROAD_HIGH_VOLUME
        reasons.append(
            AdvancedReason(
                code="BROAD_HIGH_VOLUME_ACCESS",
                message=(
                    "High request volume spans many paths in the supplied window; this is "
                    "client-level review context, not individual attribution."
                ),
                evidence_count=snapshot.request_count,
                score_contribution=API_POINTS_BROAD_HIGH_VOLUME,
            )
        )

    return active_result(
        signal=AdvancedSignalName.API_ABUSE,
        detection_name="API abuse indicator review",
        threat_category=ThreatCategory.TRAFFIC_ANOMALY,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=API_FUNCTION,
        observed_indicator=", ".join(indicators) or "no_api_abuse_indicator",
        explanation=(
            "API abuse review combines only supplied aggregate indicators. Existing "
            "rate and authentication detectors remain authoritative; their scores are "
            "not recalculated or added to this envelope."
        ),
        reasons=reasons,
        raw_points=raw_points,
        evidence_refs=_shared_evidence(snapshot),
        dedupe_key=dedupe_key(
            f"api_abuse:{snapshot.subject_ref or 'anonymous'}:{snapshot.request_count}"
        ),
        coverage_note=_coverage_note(snapshot, len(indicators)),
    )


def analyze_enumeration_review(snapshot: ApiAbuseSnapshot | None):
    """Return a separate, lower-cap enumeration-review signal."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.ENUMERATION_REVIEW,
            detection_name="Enumeration sweep review",
            threat_category=ThreatCategory.REQUEST_PATTERN,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=ENUMERATION_FUNCTION,
        )

    reasons: list[AdvancedReason] = []
    indicators: list[str] = []
    raw_points = 0.0

    if snapshot.enumeration_path_count >= ENUMERATION_PATH_MIN:
        indicators.append("ENUMERATION_PATH_SWEEP")
        raw_points += ENUMERATION_POINTS_PATH_SWEEP
        reasons.append(
            AdvancedReason(
                code="ENUMERATION_PATH_SWEEP",
                message=(
                    "Multiple candidate enumeration paths were supplied for review; this "
                    "is a path-shape observation only."
                ),
                evidence_count=snapshot.enumeration_path_count,
                score_contribution=ENUMERATION_POINTS_PATH_SWEEP,
            )
        )

    if snapshot.sequential_object_count >= SEQUENTIAL_OBJECT_MIN:
        indicators.append("SEQUENTIAL_OBJECT_IDS")
        raw_points += ENUMERATION_POINTS_SEQUENTIAL_OBJECTS
        reasons.append(
            AdvancedReason(
                code="SEQUENTIAL_OBJECT_IDS",
                message=(
                    "Sequential object identifiers were reported as a count; no "
                    "identifier values or response bodies were inspected."
                ),
                evidence_count=snapshot.sequential_object_count,
                score_contribution=ENUMERATION_POINTS_SEQUENTIAL_OBJECTS,
            )
        )

    if (
        snapshot.request_count >= HIGH_VOLUME_REQUESTS
        and snapshot.distinct_path_count >= HIGH_PATH_DIVERSITY
    ):
        indicators.append("BROAD_PATH_DISCOVERY")
        raw_points += ENUMERATION_POINTS_BROAD_PATHS
        reasons.append(
            AdvancedReason(
                code="BROAD_PATH_DISCOVERY",
                message=(
                    "High path diversity over many requests can resemble discovery; "
                    "ordinary crawlers and integrations can produce the same shape."
                ),
                evidence_count=snapshot.distinct_path_count,
                score_contribution=ENUMERATION_POINTS_BROAD_PATHS,
            )
        )

    return active_result(
        signal=AdvancedSignalName.ENUMERATION_REVIEW,
        detection_name="Enumeration sweep review",
        threat_category=ThreatCategory.REQUEST_PATTERN,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=ENUMERATION_FUNCTION,
        observed_indicator=", ".join(indicators) or "no_enumeration_indicator",
        explanation=(
            "Enumeration review is advisory path-shape context. It does not duplicate "
            "BOLA/IDOR detectors and does not claim unauthorized access."
        ),
        reasons=reasons,
        raw_points=raw_points,
        evidence_refs=_shared_evidence(snapshot),
        dedupe_key=dedupe_key(
            f"enumeration:{snapshot.subject_ref or 'anonymous'}:{snapshot.distinct_path_count}"
        ),
        coverage_note=_coverage_note(snapshot, len(indicators)),
    )


__all__ = ["analyze_api_abuse", "analyze_enumeration_review"]
