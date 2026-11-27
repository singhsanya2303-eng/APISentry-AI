"""
Trend-context adapter — MW2 (advisory only, zero points).

This adapter does NOT execute the existing SAE traffic-trend service. It accepts
a caller-supplied baseline/target window summary, preserving that service's
minimum-baseline rule as explicit structured status. The existing service is
named only as source provenance in messages.

WINDOW DEFINITION
  Both baseline and target windows are caller-supplied through
  ``TrendSnapshot.window`` plus the aggregate counts in the snapshot. No clock
  value, rolling window or fitted distribution is generated here.

THRESHOLDS / GUARDRAILS
  baseline_window_count >= minimum_baseline_windows ...... required for context;
  target_window_count > 0 ................................ required for context;
  0 <= anomalous_window_count <= target_window_count ..... required for validity;
  anomalous_window_share >= threshold_percentile ......... review note only.

No statistical accuracy, calibrated anomaly probability or confidence is claimed.
This signal always contributes zero points and never changes MW1.
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    TrendSnapshot,
)
from app.schemas.unified_risk_assessment import (
    SignalErrorCode,
    SignalStatus,
    ThreatCategory,
)
from app.services.advanced_detection.common_signal_contract import (
    active_result,
    inactive_result,
)
from app.services.advanced_detection.evidence_catalog import (
    bounded_refs,
    dedupe_key,
)

SOURCE_MODULE = "app.services.advanced_detection.trend_context_adapter"
SOURCE_FUNCTION = "adapt_trend_context"


def _invalid(snapshot: TrendSnapshot, code: SignalErrorCode, message: str):
    invalid = snapshot.model_copy(
        update={"status": SignalStatus.INVALID, "error_code": code}
    )
    return inactive_result(
        signal=AdvancedSignalName.TREND_CONTEXT,
        detection_name="Traffic trend context",
        threat_category=ThreatCategory.TRAFFIC_ANOMALY,
        snapshot=invalid,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        explanation=message,
    )


def adapt_trend_context(snapshot: TrendSnapshot | None):
    """Return zero-point trend context with explicit insufficient-evidence status."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.TREND_CONTEXT,
            detection_name="Traffic trend context",
            threat_category=ThreatCategory.TRAFFIC_ANOMALY,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
        )

    if snapshot.baseline_window_count < snapshot.minimum_baseline_windows:
        insufficient = snapshot.model_copy(
            update={
                "status": SignalStatus.UNAVAILABLE,
                "error_code": SignalErrorCode.DEPENDENCY_UNAVAILABLE,
            }
        )
        return inactive_result(
            signal=AdvancedSignalName.TREND_CONTEXT,
            detection_name="Traffic trend context",
            threat_category=ThreatCategory.TRAFFIC_ANOMALY,
            snapshot=insufficient,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
            explanation=(
                "Insufficient baseline windows were supplied for the existing SAE "
                f"minimum-baseline rule ({snapshot.baseline_window_count} < "
                f"{snapshot.minimum_baseline_windows}); no trend context is asserted."
            ),
        )

    if snapshot.target_window_count == 0:
        return _invalid(
            snapshot,
            SignalErrorCode.INVALID_OUTPUT,
            "An available trend source supplied zero target windows; no trend context "
            "is asserted.",
        )

    if snapshot.anomalous_window_count > snapshot.target_window_count:
        return _invalid(
            snapshot,
            SignalErrorCode.CONFLICTING_OUTPUT,
            "Anomalous window count exceeded the supplied target window count; "
            "conflicting context was not accepted.",
        )

    anomalous_share = (
        100.0 * snapshot.anomalous_window_count / snapshot.target_window_count
    )
    elevated = anomalous_share >= snapshot.threshold_percentile
    indicator = (
        "ANOMALOUS_WINDOW_SHARE"
        if elevated
        else "TREND_CONTEXT_WITHIN_REVIEW_RANGE"
    )
    reasons = [
        AdvancedReason(
            code=indicator,
            message=(
                f"{snapshot.anomalous_window_count}/{snapshot.target_window_count} "
                f"target windows were caller-labelled anomalous ({anomalous_share:.1f}% "
                f"vs supplied review threshold {snapshot.threshold_percentile:.1f}%). "
                "This is context only, not a calibrated anomaly probability."
            ),
            evidence_count=snapshot.anomalous_window_count,
            score_contribution=0.0,
        )
    ]
    notes = [
        f"Baseline windows supplied: {snapshot.baseline_window_count} "
        f"(minimum {snapshot.minimum_baseline_windows})."
    ]
    if snapshot.limits.truncated:
        notes.append("Trend snapshot was reported truncated.")

    return active_result(
        signal=AdvancedSignalName.TREND_CONTEXT,
        detection_name="Traffic trend context",
        threat_category=ThreatCategory.TRAFFIC_ANOMALY,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        observed_indicator=indicator,
        explanation=(
            "Existing SAE trend analysis is named for provenance only; it was not "
            "executed. This zero-cap adapter reports supplied window context and "
            "never contributes points or changes MW1."
        ),
        reasons=reasons,
        raw_points=0.0,
        evidence_refs=bounded_refs(snapshot.evidence_refs),
        dedupe_key=dedupe_key(
            f"trend:{snapshot.subject_ref or 'anonymous'}:{indicator}"
        ),
        coverage_note=" ".join(notes),
    )


__all__ = ["adapt_trend_context"]
