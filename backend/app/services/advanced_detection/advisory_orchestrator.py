"""
MW2 internal advisory orchestrator.

This is the only composition entry point for the new advanced detection layer.
It accepts validated snapshot inputs, invokes the bounded analyzers in a fixed
order and returns an ``AdvancedDetectionEnvelope``.

FUTURE COMPOSITION CONTRACT
  An unchanged MW1 ``UnifiedRiskAssessment`` may be supplied to
  ``orchestrate()``. It is passed through by reference as ``unified_assessment``;
  this module never calls ``assess_risk()``, never reads MW1 contribution fields
  for arithmetic, never adds advanced points to MW1, and never emits a combined
  score. MW1 remains the sole owner of the 0-100 unified score, its caps
  (30/30/25/10/5/0), thresholds (25/50/75), uncertainty and coverage.

  Any future combined score, endpoint, persistence or enforcement composition
  requires separate explicit authorization. This module emits advisory evidence
  only.
"""

from __future__ import annotations

from typing import Any

from app.schemas.advanced_detection_signals import (
    AdvancedDetectionEnvelope,
    AdvancedSnapshots,
    AdvisoryOrchestrationResult,
)
from app.services.advanced_detection.api_abuse_analyzer import (
    analyze_api_abuse,
    analyze_enumeration_review,
)
from app.services.advanced_detection.attribution_quality_analyzer import (
    analyze_attribution_quality,
)
from app.services.advanced_detection.coordinated_behavior_analyzer import (
    analyze_coordinated_behavior,
)
from app.services.advanced_detection.credential_abuse_analyzer import (
    analyze_credential_abuse,
)
from app.services.advanced_detection.payload_context_analyzer import (
    analyze_payload_context,
)
from app.services.advanced_detection.trend_context_adapter import (
    adapt_trend_context,
)


def _coerce_snapshots(
    snapshots: AdvancedSnapshots | dict[str, Any],
) -> AdvancedSnapshots:
    """Validate controlled inputs; unknown fields are rejected by the schema."""
    if isinstance(snapshots, AdvancedSnapshots):
        return snapshots
    return AdvancedSnapshots.model_validate(snapshots)


def build_advisory_envelope(
    snapshots: AdvancedSnapshots | dict[str, Any],
) -> AdvancedDetectionEnvelope:
    """Build the separate MW2 envelope in deterministic signal order."""
    validated = _coerce_snapshots(snapshots)
    signals = [
        analyze_coordinated_behavior(validated.behavior),
        analyze_credential_abuse(validated.credential),
        analyze_api_abuse(validated.api_abuse),
        analyze_enumeration_review(validated.api_abuse),
        analyze_payload_context(validated.payload),
        analyze_attribution_quality(validated.attribution),
        adapt_trend_context(validated.trend),
    ]
    return AdvancedDetectionEnvelope(
        subject_ref=validated.subject_ref,
        signals=signals,
    )


def orchestrate(
    snapshots: AdvancedSnapshots | dict[str, Any],
    unified_assessment: Any | None = None,
) -> AdvisoryOrchestrationResult:
    """
    Compose an UNCHANGED MW1 assessment (optional) with a separate MW2 envelope.

    No MW1 scoring function is called and no combined score is calculated.
    ``unified_assessment`` is passed through by reference for source-level
    compatibility only.
    """
    envelope = build_advisory_envelope(snapshots)
    return AdvisoryOrchestrationResult(
        unified_assessment=unified_assessment,
        advanced_envelope=envelope,
    )


__all__ = ["build_advisory_envelope", "orchestrate"]
