"""
Attribution-quality guardrail analyzer — MW2 (advisory only).

This analyzer contributes ZERO points. It exists to keep attribution uncertainty
visible alongside advanced review signals without letting ambiguity become risk.

WINDOW DEFINITION
  Caller-supplied through ``AttributionSnapshot.window``; no clock value is used.

GUARDRAIL
  Shared IP, inferred actor, missing actor/client and multiple attributed
  actors/clients are reported as coverage context only. No individual is
  inferred from an IP or client aggregate, and no score is produced.
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    AttributionSnapshot,
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

SOURCE_MODULE = "app.services.advanced_detection.attribution_quality_analyzer"
SOURCE_FUNCTION = "analyze_attribution_quality"


def analyze_attribution_quality(snapshot: AttributionSnapshot | None):
    """Return zero-point attribution context; never escalate ambiguity."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.ATTRIBUTION_QUALITY,
            detection_name="Attribution quality guardrail",
            threat_category=ThreatCategory.DATA_QUALITY,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
        )

    indicators: list[str] = []
    notes: list[str] = []
    reasons: list[AdvancedReason] = []

    if snapshot.shared_ip:
        indicators.append("SHARED_IP_CONTEXT")
        notes.append("Shared IP reported; no individual inferred from an IP.")
    if snapshot.actor_inferred:
        indicators.append("ACTOR_INFERRED")
        notes.append("Actor caller-labelled inferred; non-authoritative.")
    if snapshot.actor_missing:
        indicators.append("ACTOR_MISSING")
        notes.append("Actor attribution missing; absence is not clean.")
    if snapshot.client_missing:
        indicators.append("CLIENT_MISSING")
        notes.append("Client attribution missing; absence is not clean.")
    if snapshot.distinct_actor_count > 1 or snapshot.distinct_client_count > 1:
        indicators.append("MULTI_ACTOR_CONTEXT")
        notes.append("Multiple actors/clients present; no single-party attribution.")
    if snapshot.limits.truncated:
        notes.append("Attribution snapshot was reported truncated.")

    if indicators:
        reasons.append(
            AdvancedReason(
                code="ATTRIBUTION_AMBIGUITY_CONTEXT",
                message=(
                    "Attribution limitations were reported and are carried as coverage "
                    "context only, with zero advisory points."
                ),
                evidence_count=len(indicators),
                score_contribution=0.0,
            )
        )

    return active_result(
        signal=AdvancedSignalName.ATTRIBUTION_QUALITY,
        detection_name="Attribution quality guardrail",
        threat_category=ThreatCategory.DATA_QUALITY,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        observed_indicator=", ".join(indicators) or "attribution_context_available",
        explanation=(
            "This zero-cap guardrail records attribution quality so reviewers can see "
            "ambiguity. It never converts attribution uncertainty into suspicion."
        ),
        reasons=reasons,
        raw_points=0.0,
        evidence_refs=bounded_refs(snapshot.evidence_refs),
        dedupe_key=dedupe_key(
            f"attribution:{snapshot.subject_ref or 'anonymous'}:{len(indicators)}"
        ),
        coverage_note=" ".join(notes) or None,
    )


__all__ = ["analyze_attribution_quality"]
