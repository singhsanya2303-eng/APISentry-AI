"""Contract and MW1-compatibility tests for the MW2 advisory layer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.advanced_detection_signals import (
    AdvancedDetectionEnvelope,
    AdvancedSignalName,
    AdvancedSignalResult,
    AdvancedSnapshots,
    BehaviorSnapshot,
    DetectionWindow,
    PayloadLabelSnapshot,
    SignalLimits,
)
from app.schemas.behavior import RiskLevel
from app.schemas.unified_risk_assessment import (
    SignalErrorCode,
    SignalStatus,
    ThreatCategory,
)
from app.services.advanced_detection.advisory_orchestrator import (
    build_advisory_envelope,
    orchestrate,
)
from app.services.advanced_detection.common_signal_contract import (
    CAPS,
    cap_points,
    effective_cap,
)


def _opaque_ref(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mw2-contract-{seed}"))


def test_caps_match_the_approved_mw2_contract() -> None:
    assert effective_cap(AdvancedSignalName.COORDINATED_BEHAVIOR) == 10.0
    assert effective_cap(AdvancedSignalName.CREDENTIAL_ABUSE) == 15.0
    assert effective_cap(AdvancedSignalName.API_ABUSE) == 15.0
    assert effective_cap(AdvancedSignalName.ENUMERATION_REVIEW) == 5.0
    assert effective_cap(AdvancedSignalName.PAYLOAD_CONTEXT) == 10.0
    assert effective_cap(AdvancedSignalName.ATTRIBUTION_QUALITY) == 0.0
    assert effective_cap(AdvancedSignalName.TREND_CONTEXT) == 0.0
    assert cap_points(99.0, AdvancedSignalName.API_ABUSE) == 15.0
    assert cap_points(-4.0, AdvancedSignalName.API_ABUSE) == 0.0
    assert len(CAPS) == 7


def test_missing_snapshot_is_explicit_inactive_not_clean() -> None:
    envelope = build_advisory_envelope({})

    assert isinstance(envelope, AdvancedDetectionEnvelope)
    assert envelope.schema_version == "mw2-advanced-signals/v1"
    assert envelope.advisory_only is True
    assert "no combined score" not in str(envelope.confidence_policy).lower()
    assert len(envelope.signals) == 7
    assert [signal.signal for signal in envelope.signals] == [
        AdvancedSignalName.COORDINATED_BEHAVIOR,
        AdvancedSignalName.CREDENTIAL_ABUSE,
        AdvancedSignalName.API_ABUSE,
        AdvancedSignalName.ENUMERATION_REVIEW,
        AdvancedSignalName.PAYLOAD_CONTEXT,
        AdvancedSignalName.ATTRIBUTION_QUALITY,
        AdvancedSignalName.TREND_CONTEXT,
    ]
    assert all(signal.status == SignalStatus.MISSING for signal in envelope.signals)
    assert all(signal.points == 0.0 for signal in envelope.signals)
    assert all(signal.severity.value == "LOW" for signal in envelope.signals)
    assert "not clean" in " ".join(
        signal.coverage_note or "" for signal in envelope.signals
    )


def test_error_and_invalid_statuses_are_structured_and_zero_pointed() -> None:
    error_snapshot = BehaviorSnapshot(
        status=SignalStatus.ERROR,
        error_code=SignalErrorCode.DETECTOR_TIMEOUT,
    )
    invalid_snapshot = PayloadLabelSnapshot(status=SignalStatus.INVALID)

    envelope = build_advisory_envelope(
        {
            "behavior": error_snapshot,
            "credential": {"status": SignalStatus.UNAVAILABLE.value},
            "api_abuse": {"status": SignalStatus.INVALID.value},
            "payload": invalid_snapshot,
        }
    )
    by_signal = {signal.signal: signal for signal in envelope.signals}

    behavior = by_signal[AdvancedSignalName.COORDINATED_BEHAVIOR]
    assert behavior.status == SignalStatus.ERROR
    assert behavior.error_code == SignalErrorCode.DETECTOR_TIMEOUT
    assert behavior.points == 0.0
    assert invalid_snapshot.error_code == SignalErrorCode.INVALID_OUTPUT

    api = by_signal[AdvancedSignalName.API_ABUSE]
    assert api.status == SignalStatus.INVALID
    assert api.error_code == SignalErrorCode.INVALID_OUTPUT
    assert api.points == 0.0
    assert invalid_snapshot.error_code == SignalErrorCode.INVALID_OUTPUT


def test_window_timestamp_is_supplied_only() -> None:
    end = datetime(2026, 11, 22, 6, 0, tzinfo=timezone.utc)
    envelope = build_advisory_envelope(
        {
            "behavior": {
                "status": SignalStatus.AVAILABLE.value,
                "window": {"end": end.isoformat(), "duration_seconds": 60.0},
            }
        }
    )
    behavior = envelope.signals[0]

    assert behavior.timestamp == end
    assert behavior.window is not None
    assert behavior.window.duration_seconds == 60.0

    no_window = build_advisory_envelope(
        {"behavior": {"status": SignalStatus.AVAILABLE.value}}
    )
    assert no_window.signals[0].timestamp is None
    assert no_window.signals[0].window is None


def test_unknown_and_sensitive_fields_are_rejected_by_input_contract() -> None:
    with pytest.raises(ValidationError):
        AdvancedSnapshots.model_validate(
            {"behavior": {"status": "available", "raw_request_id": "abc"}}
        )
    with pytest.raises(ValidationError):
        PayloadLabelSnapshot.model_validate(
            {
                "status": "available",
                "labels": ["anomalous"],
                "decision_score": 4.2,
            }
        )
    with pytest.raises(ValidationError):
        PayloadLabelSnapshot.model_validate(
            {
                "status": "available",
                "labels": ["anomalous"],
                "low_margin": True,
            }
        )
    with pytest.raises(ValidationError):
        PayloadLabelSnapshot.model_validate(
            {
                "status": "available",
                "labels": ["anomalous"],
                "payload_echo": "sensitive",
            }
        )
    with pytest.raises(ValidationError):
        build_advisory_envelope({"unexpected_top_level": True})


def test_evidence_refs_must_be_opaque_uuid5_and_bounded() -> None:
    opaque = _opaque_ref("valid")
    snapshot = BehaviorSnapshot(
        status=SignalStatus.AVAILABLE,
        evidence_refs=[opaque, _opaque_ref("second")],
        limits=SignalLimits(truncated=True),
    )
    assert snapshot.evidence_refs == [opaque, _opaque_ref("second")]

    with pytest.raises(ValidationError):
        BehaviorSnapshot(
            status=SignalStatus.AVAILABLE,
            evidence_refs=["raw-request-id-123"],
        )


def test_result_validator_rejects_points_above_cap_and_inactive_points() -> None:
    common = {
        "signal": AdvancedSignalName.API_ABUSE,
        "detection_name": "Cap validator check",
        "threat_category": ThreatCategory.TRAFFIC_ANOMALY,
        "severity": RiskLevel.LOW,
        "observed_indicator": "synthetic",
        "explanation": "Synthetic validator check.",
        "source_module": "test.contract",
        "source_function": "validator_check",
        "cap": 15.0,
    }
    with pytest.raises(ValidationError):
        AdvancedSignalResult(**common, status=SignalStatus.AVAILABLE, points=99.0)
    with pytest.raises(ValidationError):
        AdvancedSignalResult(
            **common,
            status=SignalStatus.MISSING,
            points=1.0,
        )


def test_orchestrator_passes_mw1_through_without_scoring(monkeypatch) -> None:
    import app.services.unified_risk_assessment_service as mw1_service

    def _forbidden(*args, **kwargs):
        raise AssertionError("MW1 assess_risk must not be called by MW2")

    monkeypatch.setattr(mw1_service, "assess_risk", _forbidden, raising=True)

    mw1_result = object()
    snapshots = AdvancedSnapshots(subject_ref="subject-1")
    result = orchestrate(snapshots, unified_assessment=mw1_result)

    assert result.unified_assessment is mw1_result
    assert result.advanced_envelope.subject_ref == "subject-1"
    assert result.advisory_only is True
    assert not hasattr(result, "risk_score")
    assert not hasattr(result.advanced_envelope, "risk_score")


def test_envelope_is_deterministic_for_identical_inputs() -> None:
    payload = {
        "subject_ref": "stable-subject",
        "behavior": {
            "status": SignalStatus.AVAILABLE.value,
            "request_count": 60,
            "burst_count": 3,
        },
        "api_abuse": {
            "status": SignalStatus.AVAILABLE.value,
            "request_count": 60,
            "peak_requests_per_window": 70,
            "window_request_threshold": 50,
        },
        "attribution": {
            "status": SignalStatus.AVAILABLE.value,
            "shared_ip": True,
        },
    }
    first = build_advisory_envelope(payload).model_dump_json()
    second = build_advisory_envelope(payload).model_dump_json()

    assert first == second


def test_detection_window_is_a_callers_construct() -> None:
    with pytest.raises(ValidationError):
        DetectionWindow.model_validate({"duration_seconds": -1, "unknown": "x"})
