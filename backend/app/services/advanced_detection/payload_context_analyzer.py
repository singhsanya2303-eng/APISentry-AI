"""
Payload-label context analyzer — MW2 (advisory only).

The frozen classifier is NOT loaded or called. Only caller-supplied categorical
labels are accepted. ``extra='forbid'`` on ``PayloadLabelSnapshot`` rejects any
decision score, low-margin flag, payload echo, raw header or other sensitive
field before analysis begins.

WINDOW DEFINITION
  Caller-supplied through ``PayloadLabelSnapshot.window``; no clock value is used.

THRESHOLDS (advisory review only, bounded to 10 points)
  each anomalous categorical label .... 2.5 points, capped at 10;
  benign-only labels .................. 0 points;
  empty label set ..................... structured INVALID result;
  artifact hash mismatch .............. structured INVALID result, no context accepted.

No classifier margin, low-margin flag or payload text is represented as risk,
confidence or severity.
"""

from __future__ import annotations

from app.schemas.advanced_detection_signals import (
    AdvancedReason,
    AdvancedSignalName,
    PayloadLabelSnapshot,
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

SOURCE_MODULE = "app.services.advanced_detection.payload_context_analyzer"
SOURCE_FUNCTION = "analyze_payload_context"

FROZEN_CLASSIFIER_SHA256 = (
    "2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc"
)
POINTS_PER_ANOMALOUS_LABEL = 2.5


def analyze_payload_context(snapshot: PayloadLabelSnapshot | None):
    """Return bounded payload-label review context; never call the classifier."""
    if snapshot is None or snapshot.status.value != "available":
        return inactive_result(
            signal=AdvancedSignalName.PAYLOAD_CONTEXT,
            detection_name="Payload classifier label context",
            threat_category=ThreatCategory.PAYLOAD,
            snapshot=snapshot,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
        )

    if not snapshot.labels:
        invalid = snapshot.model_copy(
            update={
                "status": SignalStatus.INVALID,
                "error_code": SignalErrorCode.INVALID_OUTPUT,
            }
        )
        return inactive_result(
            signal=AdvancedSignalName.PAYLOAD_CONTEXT,
            detection_name="Payload classifier label context",
            threat_category=ThreatCategory.PAYLOAD,
            snapshot=invalid,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
            explanation=(
                "An available payload source supplied no categorical labels; this is "
                "not a clean result and contributes zero points."
            ),
        )

    if (
        snapshot.artifact_sha256 is not None
        and snapshot.artifact_sha256.lower() != FROZEN_CLASSIFIER_SHA256
    ):
        conflicting = snapshot.model_copy(
            update={
                "status": SignalStatus.INVALID,
                "error_code": SignalErrorCode.CONFLICTING_OUTPUT,
            }
        )
        return inactive_result(
            signal=AdvancedSignalName.PAYLOAD_CONTEXT,
            detection_name="Payload classifier label context",
            threat_category=ThreatCategory.PAYLOAD,
            snapshot=conflicting,
            source_module=SOURCE_MODULE,
            source_function=SOURCE_FUNCTION,
            explanation=(
                "Supplied artifact provenance did not match the frozen research "
                "artifact reference; no label context was accepted."
            ),
        )

    anomalous_count = sum(1 for label in snapshot.labels if label == "anomalous")
    benign_count = len(snapshot.labels) - anomalous_count
    raw_points = POINTS_PER_ANOMALOUS_LABEL * anomalous_count

    reasons: list[AdvancedReason] = []
    if anomalous_count:
        reasons.append(
            AdvancedReason(
                code="ANOMALOUS_LABEL_CONTEXT",
                message=(
                    f"{anomalous_count} categorical anomalous label(s) were supplied. "
                    "Labels are review context only, not calibrated risk."
                ),
                evidence_count=anomalous_count,
                score_contribution=POINTS_PER_ANOMALOUS_LABEL,
            )
        )
    else:
        reasons.append(
            AdvancedReason(
                code="BENIGN_LABEL_CONTEXT",
                message=(
                    f"{benign_count} categorical benign label(s) were supplied; this "
                    "does not prove that unseen traffic is clean."
                ),
                evidence_count=benign_count,
                score_contribution=0.0,
            )
        )

    coverage_notes: list[str] = []
    if snapshot.artifact_sha256 is None:
        coverage_notes.append(
            "No artifact provenance was supplied; labels remain review-only context."
        )
    else:
        coverage_notes.append(
            "Artifact provenance matched the frozen research reference; no model was "
            "loaded or executed."
        )
    if snapshot.limits.truncated:
        coverage_notes.append("Label set was reported truncated.")
    if anomalous_count == 1 and len(snapshot.labels) > 1:
        coverage_notes.append(
            "A single anomalous label among several is a weak signal and is not a "
            "suspicious conclusion."
        )

    return active_result(
        signal=AdvancedSignalName.PAYLOAD_CONTEXT,
        detection_name="Payload classifier label context",
        threat_category=ThreatCategory.PAYLOAD,
        snapshot=snapshot,
        source_module=SOURCE_MODULE,
        source_function=SOURCE_FUNCTION,
        observed_indicator=(
            f"anomalous_label_count={anomalous_count};benign_label_count={benign_count}"
        ),
        explanation=(
            "Only categorical labels were read. Decision margins, low-margin flags, "
            "payload echoes and classifier internals are excluded by the input "
            "contract and are not represented as scores or confidence."
        ),
        reasons=reasons,
        raw_points=raw_points,
        evidence_refs=bounded_refs(snapshot.evidence_refs),
        dedupe_key=dedupe_key(
            f"payload:{snapshot.subject_ref or 'anonymous'}:{anomalous_count}:{benign_count}"
        ),
        coverage_note=" ".join(coverage_notes),
    )


__all__ = ["analyze_payload_context"]
