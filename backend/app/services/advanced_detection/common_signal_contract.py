"""
Shared construction rules for MW2 advisory signals.

This module owns:
  - the per-signal advisory caps;
  - the inactive/missing-signal representation;
  - bounded point calculation and existing severity-threshold reuse.

It does NOT own the MW1 unified score. Points produced here stay inside the MW2
envelope and are never added to MW1's 0-100 assessment.
"""

from __future__ import annotations

from typing import Any, Sequence

from app.detection.risk_scorer import get_risk_level
from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    AdvancedSignalResult,
    SignalLimits,
    SnapshotBase,
)
from app.schemas.unified_risk_assessment import (
    SignalErrorCode,
    SignalStatus,
    ThreatCategory,
)

CAPS: dict[AdvancedSignalName, float] = {
    AdvancedSignalName.COORDINATED_BEHAVIOR: 10.0,
    AdvancedSignalName.CREDENTIAL_ABUSE: 15.0,
    AdvancedSignalName.API_ABUSE: 15.0,
    AdvancedSignalName.ENUMERATION_REVIEW: 5.0,
    AdvancedSignalName.PAYLOAD_CONTEXT: 10.0,
    AdvancedSignalName.ATTRIBUTION_QUALITY: 0.0,
    AdvancedSignalName.TREND_CONTEXT: 0.0,
}

# Attribution and trend are guardrails: their cap is zero, so the generic
# validator must allow a zero-cap result object.
_ZERO_CAP_SIGNALS = frozenset(
    {
        AdvancedSignalName.ATTRIBUTION_QUALITY,
        AdvancedSignalName.TREND_CONTEXT,
    }
)

STATUS_NOTES: dict[SignalStatus, str] = {
    SignalStatus.MISSING: "Snapshot was not supplied; zero points were assigned. Missing is not clean.",
    SignalStatus.UNAVAILABLE: "Signal source was reported unavailable; zero points were assigned.",
    SignalStatus.ERROR: "Detector reported an error; zero points were assigned.",
    SignalStatus.INVALID: "Snapshot failed validation; zero points were assigned.",
}


def effective_cap(signal: AdvancedSignalName) -> float:
    """Return the documented advisory cap for a signal."""
    return CAPS[signal]


def cap_points(raw: float, signal: AdvancedSignalName) -> float:
    """Clamp and round a raw advisory point total to the signal cap."""
    capped = min(max(float(raw), 0.0), effective_cap(signal))
    return round(capped, 1)


def _timestamp(snapshot: SnapshotBase) -> Any | None:
    """Use the supplied window end; never generate a wall-clock timestamp."""
    if snapshot.window is None:
        return None
    return snapshot.window.end


def _error_code(snapshot: SnapshotBase) -> SignalErrorCode | None:
    return snapshot.error_code


def inactive_result(
    *,
    signal: AdvancedSignalName,
    detection_name: str,
    threat_category: ThreatCategory,
    snapshot: SnapshotBase | None,
    source_module: str,
    source_function: str,
    explanation: str | None = None,
) -> AdvancedSignalResult:
    """Build an explicit zero-point result for a non-available snapshot."""
    status = snapshot.status if snapshot is not None else SignalStatus.MISSING
    note = STATUS_NOTES.get(status, STATUS_NOTES[SignalStatus.MISSING])
    window = snapshot.window if snapshot is not None else None
    return AdvancedSignalResult(
        signal=signal,
        detection_name=detection_name,
        threat_category=threat_category,
        severity=get_risk_level(0.0),
        observed_indicator="signal_not_available",
        explanation=explanation or note,
        evidence_refs=[],
        source_module=source_module,
        source_function=source_function,
        window=window,
        timestamp=_timestamp(snapshot) if snapshot is not None else None,
        status=status,
        error_code=_error_code(snapshot) if snapshot is not None else None,
        points=0.0,
        cap=effective_cap(signal),
        reasons=[],
        coverage_note=note,
        subject_ref=snapshot.subject_ref if snapshot is not None else None,
        dedupe_key=f"{signal.value}:inactive",
        limits=snapshot.limits if snapshot is not None else SignalLimits(),
    )


def active_result(
    *,
    signal: AdvancedSignalName,
    detection_name: str,
    threat_category: ThreatCategory,
    snapshot: SnapshotBase,
    source_module: str,
    source_function: str,
    observed_indicator: str,
    explanation: str,
    reasons: Sequence[AdvancedReason],
    raw_points: float,
    evidence_refs: Sequence[str] | None = None,
    dedupe_key: str | None = None,
    source_confidence: float | None = None,
    coverage_note: str | None = None,
) -> AdvancedSignalResult:
    """Build a bounded advisory result from validated indicators."""
    points = cap_points(raw_points, signal)
    severity = get_risk_level(points)
    return AdvancedSignalResult(
        signal=signal,
        detection_name=detection_name,
        threat_category=threat_category,
        severity=severity,
        observed_indicator=observed_indicator,
        explanation=explanation,
        evidence_refs=list(evidence_refs or []),
        source_module=source_module,
        source_function=source_function,
        window=snapshot.window,
        timestamp=_timestamp(snapshot),
        status=SignalStatus.AVAILABLE,
        error_code=None,
        points=points,
        cap=effective_cap(signal),
        reasons=list(reasons)[:25],
        source_confidence=source_confidence,
        coverage_note=coverage_note,
        subject_ref=snapshot.subject_ref,
        dedupe_key=dedupe_key or f"{signal.value}:{snapshot.subject_ref or 'anonymous'}",
        limits=snapshot.limits,
    )


def unavailable_cap_message(signal: AdvancedSignalName) -> str:
    """Explain why a zero-cap guardrail signal still appears in the envelope."""
    if signal in _ZERO_CAP_SIGNALS:
        return "Guardrail signal: contributes context only, never points."
    return ""
