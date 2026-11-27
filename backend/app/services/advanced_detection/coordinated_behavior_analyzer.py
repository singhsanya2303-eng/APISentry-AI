"""
Behavioural bot-indicator analyzer — MW2 (advisory only).

Reuses aggregated outputs of the existing bot-detection pipeline; it does NOT
re-implement rate, brute-force, User-Agent or request-pattern detectors.

WINDOW DEFINITION
  The observation window is supplied by the caller through ``BehaviorSnapshot.window``.
  No clock value is generated here. If no window is supplied, ``window`` and
  ``timestamp`` are null and the result remains deterministic.

THRESHOLDS (advisory review only, bounded to 10 points)
  high request frequency .............. request_count >= 50
  repeated dominant path .............. dominant_path_share >= 0.8 and requests >= 8
  suspicious timing ................... burst_count >= 3 or inter_arrival_cv <= 0.05 with >= 10 requests
  unusual navigation sequence ......... sequence_repeat_count >= 3
  sudden behavioural change ........... behavior_change_flags present
  cross-client coordination ........... coordinated_group_count >= 2 with >= 2 clients
  2.5 points per indicator, capped at 10. One weak indicator never produces a
  suspicious classification; existing bot labels stay authoritative.
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    BehaviorSnapshot,
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

SOURCE_MODULE = "app.services.advanced_detection.coordinated_behavior_analyzer"
SOURCE_FUNCTION = "analyze_coordinated_behavior"

HIGH_FREQUENCY_REQUESTS = 50
REPEAT_MIN_REQUESTS = 8
DOMINANT_PATH_SHARE = 0.8
BURST_MIN_COUNT = 3
MAX_INTER_ARRIVAL_CV = 0.05
CV_MIN_REQUESTS = 10
SEQUENCE_REPEAT_MIN = 3
COORDINATION_MIN_GROUPS = 2
COORDINATION_MIN_CLIENTS = 2
POINTS_PER_INDICATOR = 2.5


def analyze_coordinated_behavior(snapshot: BehaviorSnapshot | None):
    """Return a bounded, explainable behavioural review signal."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.COORDINATED_BEHAVIOR,
            detection_name="Behavioural bot indicator review",
            threat_category=ThreatCategory.BOT_AUTOMATION,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
        )

    reasons: list[AdvancedReason] = []
    indicator_codes: list[str] = []

    def add(code: str, message: str, evidence_count: int) -> None:
        indicator_codes.append(code)
        reasons.append(
            AdvancedReason(
                code=code,
                message=message,
                evidence_count=evidence_count,
                score_contribution=POINTS_PER_INDICATOR,
            )
        )

    if snapshot.request_count >= HIGH_FREQUENCY_REQUESTS:
        add(
            "HIGH_REQUEST_FREQUENCY",
            f"{snapshot.request_count} attributed requests were supplied in the window; "
            "this is a review indicator, not proof of automation or malice.",
            snapshot.request_count,
        )

    if (
        snapshot.dominant_path_share >= DOMINANT_PATH_SHARE
        and snapshot.request_count >= REPEAT_MIN_REQUESTS
    ):
        add(
            "REPEATED_DOMINANT_PATH",
            "A dominant path share was observed over enough requests to review for "
            "automation-like repetition.",
            snapshot.request_count,
        )

    suspicious_timing = snapshot.burst_count >= BURST_MIN_COUNT or (
        snapshot.inter_arrival_cv is not None
        and snapshot.inter_arrival_cv <= MAX_INTER_ARRIVAL_CV
        and snapshot.request_count >= CV_MIN_REQUESTS
    )
    if suspicious_timing:
        add(
            "SUSPICIOUS_REQUEST_TIMING",
            "Supplied timing indicators show either repeated bursts or unusually "
            "regular inter-arrival intervals; scheduling or client retries can produce this.",
            snapshot.burst_count,
        )

    if snapshot.sequence_repeat_count >= SEQUENCE_REPEAT_MIN:
        add(
            "REPEATED_NAVIGATION_SEQUENCE",
            "A repeated endpoint navigation sequence was supplied for review.",
            snapshot.sequence_repeat_count,
        )

    if snapshot.behavior_change_flags:
        add(
            "SUDDEN_BEHAVIOUR_CHANGE",
            "Caller-supplied behavioural change flags are present; this is a drift "
            "review indicator, not a certainty statement.",
            len(snapshot.behavior_change_flags),
        )

    if (
        snapshot.coordinated_group_count >= COORDINATION_MIN_GROUPS
        and snapshot.client_count >= COORDINATION_MIN_CLIENTS
    ):
        add(
            "CROSS_CLIENT_COORDINATION",
            "Multiple client groups share supplied coordination indicators; client-level "
            "attribution remains separate and no individual is inferred from an IP.",
            snapshot.coordinated_group_count,
        )

    raw_points = POINTS_PER_INDICATOR * len(indicator_codes)
    explanation = (
        f"{len(indicator_codes)} behavioural indicator(s) were reviewed from existing "
        "detector summaries. Existing bot outputs are reused as context only and are "
        "not rescored here."
    )
    if snapshot.bot_risk_score is not None:
        explanation += (
            f" Existing bot score {snapshot.bot_risk_score:.1f}/100 was preserved as "
            "context and was not added to these points."
        )
    if snapshot.classification:
        explanation += f" Existing bot label: {snapshot.classification}."

    coverage_note = None
    if snapshot.limits.truncated:
        coverage_note = "Source page was truncated; indicator coverage is reduced."
    elif len(indicator_codes) < 2:
        coverage_note = (
            "Fewer than two indicators were present; a single weak signal is not "
            "sufficient to infer suspicious automation."
        )

    return active_result(
        signal=AdvancedSignalName.COORDINATED_BEHAVIOR,
        detection_name="Behavioural bot indicator review",
        threat_category=ThreatCategory.BOT_AUTOMATION,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        observed_indicator=", ".join(indicator_codes) or "no_behavioural_indicator",
        explanation=explanation,
        reasons=reasons,
        raw_points=raw_points,
        evidence_refs=bounded_refs(snapshot.evidence_refs),
        dedupe_key=dedupe_key(
            f"coordinated:{snapshot.subject_ref or 'anonymous'}:"
            f"{snapshot.classification or 'unlabelled'}"
        ),
        coverage_note=coverage_note,
    )


__all__ = ["analyze_coordinated_behavior"]
