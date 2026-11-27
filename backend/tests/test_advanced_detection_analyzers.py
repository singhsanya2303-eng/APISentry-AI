"""Focused tests for each MW2 analyzer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.advanced_detection_signals import (
    AdvancedSignalName,
    ApiAbuseSnapshot,
    AttributionSnapshot,
    BehaviorSnapshot,
    CredentialSnapshot,
    PayloadLabelSnapshot,
    TrendSnapshot,
)
from app.schemas.unified_risk_assessment import (
    SignalErrorCode,
    SignalStatus,
    ThreatCategory,
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
    FROZEN_CLASSIFIER_SHA256,
    analyze_payload_context,
)
from app.services.advanced_detection.trend_context_adapter import (
    adapt_trend_context,
)


def _ref(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mw2-analyzer-{seed}"))


def _available_window() -> dict:
    end = datetime(2026, 11, 22, 6, 30, tzinfo=timezone.utc)
    return {
        "start": end.isoformat(),
        "end": end.isoformat(),
        "duration_seconds": 60.0,
        "scope": "synthetic",
    }


# --- Behavioural bot review -------------------------------------------------


def test_behavior_normal_traffic_has_no_indicators() -> None:
    result = analyze_coordinated_behavior(
        BehaviorSnapshot(
            status=SignalStatus.AVAILABLE,
            subject_ref="normal",
            request_count=12,
            distinct_path_count=6,
            distinct_method_count=2,
            dominant_path_share=0.3,
            stable_user_agent=True,
            classification="automation_benign",
            bot_risk_score=5.0,
        )
    )

    assert result.signal == AdvancedSignalName.COORDINATED_BEHAVIOR
    assert result.status == SignalStatus.AVAILABLE
    assert result.points == 0.0
    assert result.cap == 10.0
    assert result.threat_category == ThreatCategory.BOT_AUTOMATION
    assert result.observed_indicator == "no_behavioural_indicator"
    assert "Fewer than two indicators" in (result.coverage_note or "")
    assert "5.0/100" in result.explanation


def test_behavior_suspicious_pattern_is_capped_and_explained() -> None:
    result = analyze_coordinated_behavior(
        BehaviorSnapshot(
            status=SignalStatus.AVAILABLE,
            subject_ref="suspicious",
            window=_available_window(),
            request_count=60,
            dominant_path_share=0.9,
            burst_count=3,
            sequence_repeat_count=4,
            behavior_change_flags=["new_path_set"],
            coordinated_group_count=2,
            client_count=5,
            evidence_refs=[_ref("behavior-a"), _ref("behavior-b")],
        )
    )

    assert result.points == 10.0
    assert result.cap == 10.0
    assert len(result.reasons) == 6
    assert result.timestamp == datetime(2026, 11, 22, 6, 30, tzinfo=timezone.utc)
    assert result.evidence_refs == [_ref("behavior-a"), _ref("behavior-b")]
    assert result.dedupe_key is not None
    assert result.severity.value == "LOW"


def test_behavior_boundary_thresholds() -> None:
    below = analyze_coordinated_behavior(
        BehaviorSnapshot(
            status=SignalStatus.AVAILABLE,
            request_count=49,
            dominant_path_share=0.79,
        )
    )
    at_boundary = analyze_coordinated_behavior(
        BehaviorSnapshot(
            status=SignalStatus.AVAILABLE,
            request_count=50,
            dominant_path_share=0.8,
            burst_count=3,
            inter_arrival_cv=0.05,
            sequence_repeat_count=3,
        )
    )

    assert "HIGH_REQUEST_FREQUENCY" not in below.observed_indicator
    assert "REPEATED_DOMINANT_PATH" not in below.observed_indicator
    assert {"HIGH_REQUEST_FREQUENCY", "REPEATED_DOMINANT_PATH"} <= set(
        at_boundary.observed_indicator.split(", ")
    )
    assert "SUSPICIOUS_REQUEST_TIMING" in at_boundary.observed_indicator
    assert "REPEATED_NAVIGATION_SEQUENCE" in at_boundary.observed_indicator
    assert at_boundary.points == 10.0


def test_behavior_failed_detector_is_not_clean() -> None:
    result = analyze_coordinated_behavior(
        BehaviorSnapshot(
            status=SignalStatus.ERROR,
            error_code=SignalErrorCode.DETECTOR_EXCEPTION,
        )
    )
    assert result.status == SignalStatus.ERROR
    assert result.error_code == SignalErrorCode.DETECTOR_EXCEPTION
    assert result.points == 0.0
    assert result.observed_indicator == "signal_not_available"


# --- Credential abuse review ------------------------------------------------


def test_credential_normal_traffic_has_no_points() -> None:
    result = analyze_credential_abuse(
        CredentialSnapshot(
            status=SignalStatus.AVAILABLE,
            failure_count=2,
            success_count=20,
            distinct_account_keys=2,
        )
    )
    assert result.points == 0.0
    assert result.status == SignalStatus.AVAILABLE
    assert result.observed_indicator == "no_auth_abuse_indicator"


def test_credential_spray_shape_is_bounded_and_privacy_safe() -> None:
    result = analyze_credential_abuse(
        CredentialSnapshot(
            status=SignalStatus.AVAILABLE,
            subject_ref="auth-window",
            failure_count=7,
            success_count=1,
            distinct_account_keys=4,
            distinct_client_count=1,
            auth_endpoint_count=1,
            success_after_failure_count=2,
            shared_ip_failure_groups=1,
        )
    )

    assert result.points == 13.0
    assert result.cap == 15.0
    assert len(result.reasons) == 3
    assert "Shared-IP" in (result.coverage_note or "")
    assert "No credential, account value" in result.explanation
    assert "alice" not in str(result.model_dump())
    assert "password" not in str(result.model_dump()).lower()


def test_credential_single_weak_success_indicator_is_not_suspicious() -> None:
    result = analyze_credential_abuse(
        CredentialSnapshot(
            status=SignalStatus.AVAILABLE,
            failure_count=1,
            success_after_failure_count=1,
        )
    )
    assert result.points == 3.0
    assert result.severity.value == "LOW"
    assert "Only one weak indicator" in (result.coverage_note or "")


def test_credential_missing_snapshot_is_zero_pointed() -> None:
    result = analyze_credential_abuse(None)
    assert result.status == SignalStatus.MISSING
    assert result.points == 0.0
    assert result.cap == 15.0


# --- API abuse and enumeration review --------------------------------------


def _api_snapshot(**overrides) -> ApiAbuseSnapshot:
    values = {
        "status": SignalStatus.AVAILABLE,
        "subject_ref": "api-window",
        "window": _available_window(),
        "request_count": 60,
        "distinct_path_count": 25,
        "distinct_method_count": 5,
        "error_4xx_count": 12,
        "error_5xx_count": 6,
        "burst_count": 3,
        "peak_requests_per_window": 70,
        "window_request_threshold": 50,
        "enumeration_path_count": 4,
        "sequential_object_count": 6,
        "rare_method_count": 1,
        "scraping_path_repeat_count": 10,
    }
    values.update(overrides)
    return ApiAbuseSnapshot.model_validate(values)


def test_api_abuse_combines_multiple_indicators_without_intent_claim() -> None:
    result = analyze_api_abuse(_api_snapshot())

    assert result.signal == AdvancedSignalName.API_ABUSE
    assert result.points == 14.0
    assert result.cap == 15.0
    assert len(result.reasons) == 6
    assert result.threat_category == ThreatCategory.TRAFFIC_ANOMALY
    assert "not a calibrated anomaly probability" in " ".join(
        reason.message for reason in result.reasons
    )
    assert "malicious intent" in " ".join(
        reason.message for reason in result.reasons
    )


def test_enumeration_review_is_separate_and_lower_cap() -> None:
    result = analyze_enumeration_review(_api_snapshot())

    assert result.signal == AdvancedSignalName.ENUMERATION_REVIEW
    assert result.points == 5.0
    assert result.cap == 5.0
    assert len(result.reasons) == 3
    assert "BOLA/IDOR" in result.explanation


def test_api_abuse_thresholds_are_boundary_exact() -> None:
    below = analyze_api_abuse(
        _api_snapshot(
            request_count=1,
            distinct_path_count=1,
            peak_requests_per_window=49,
            burst_count=2,
            error_4xx_count=9,
            error_5xx_count=4,
            distinct_method_count=3,
            rare_method_count=0,
            scraping_path_repeat_count=7,
        )
    )
    assert below.points == 0.0
    assert below.observed_indicator == "no_api_abuse_indicator"

    at_boundary = analyze_api_abuse(
        _api_snapshot(
            request_count=1,
            distinct_path_count=1,
            peak_requests_per_window=50,
            burst_count=3,
            error_4xx_count=10,
            error_5xx_count=5,
            distinct_method_count=4,
            rare_method_count=0,
            scraping_path_repeat_count=8,
        )
    )
    assert at_boundary.points == 12.5
    assert "WINDOW_VOLUME_DEVIATION" in at_boundary.observed_indicator
    assert "BROAD_HIGH_VOLUME_ACCESS" not in at_boundary.observed_indicator


def test_api_abuse_missing_and_invalid_snapshots_are_zero_pointed() -> None:
    missing = analyze_api_abuse(None)
    invalid = analyze_enumeration_review(
        ApiAbuseSnapshot(status=SignalStatus.INVALID)
    )
    assert missing.status == SignalStatus.MISSING
    assert missing.points == 0.0
    assert invalid.status == SignalStatus.INVALID
    assert invalid.points == 0.0
    assert invalid.error_code == SignalErrorCode.INVALID_OUTPUT


# --- Payload label context --------------------------------------------------


def test_payload_labels_only_are_capped_and_do_not_load_model() -> None:
    result = analyze_payload_context(
        PayloadLabelSnapshot(
            status=SignalStatus.AVAILABLE,
            subject_ref="payload-window",
            labels=["anomalous"] * 6 + ["benign"],
            artifact_sha256=FROZEN_CLASSIFIER_SHA256,
        )
    )

    assert result.points == 10.0
    assert result.cap == 10.0
    assert result.observed_indicator == "anomalous_label_count=6;benign_label_count=1"
    assert "no model was" in result.explanation or "no model was" in (
        result.coverage_note or ""
    )


def test_payload_benign_labels_are_not_a_clean_certificate() -> None:
    result = analyze_payload_context(
        PayloadLabelSnapshot(
            status=SignalStatus.AVAILABLE,
            labels=["benign", "benign"],
        )
    )
    assert result.points == 0.0
    assert "does not prove" in " ".join(reason.message for reason in result.reasons)
    assert "No artifact provenance" in (result.coverage_note or "")


def test_payload_empty_labels_and_conflicting_artifact_are_invalid() -> None:
    empty = analyze_payload_context(
        PayloadLabelSnapshot(status=SignalStatus.AVAILABLE, labels=[])
    )
    conflicting = analyze_payload_context(
        PayloadLabelSnapshot(
            status=SignalStatus.AVAILABLE,
            labels=["anomalous"],
            artifact_sha256="b" * 64,
        )
    )

    assert empty.status == SignalStatus.INVALID
    assert empty.error_code == SignalErrorCode.INVALID_OUTPUT
    assert empty.points == 0.0
    assert conflicting.status == SignalStatus.INVALID
    assert conflicting.error_code == SignalErrorCode.CONFLICTING_OUTPUT
    assert conflicting.points == 0.0


# --- Attribution guardrail --------------------------------------------------


def test_attribution_ambiguity_is_context_only() -> None:
    result = analyze_attribution_quality(
        AttributionSnapshot(
            status=SignalStatus.AVAILABLE,
            shared_ip=True,
            actor_inferred=True,
            actor_missing=True,
            distinct_actor_count=3,
        )
    )

    assert result.points == 0.0
    assert result.cap == 0.0
    assert result.status == SignalStatus.AVAILABLE
    assert result.threat_category == ThreatCategory.DATA_QUALITY
    assert "no individual inferred" in (result.coverage_note or "")
    assert all(reason.score_contribution == 0.0 for reason in result.reasons)


def test_attribution_missing_snapshot_remains_explicit() -> None:
    result = analyze_attribution_quality(None)
    assert result.status == SignalStatus.MISSING
    assert result.points == 0.0
    assert result.cap == 0.0


# --- Trend context adapter --------------------------------------------------


def test_trend_insufficient_baseline_is_structured_unavailable() -> None:
    result = adapt_trend_context(
        TrendSnapshot(
            status=SignalStatus.AVAILABLE,
            baseline_window_count=3,
            target_window_count=5,
            anomalous_window_count=1,
            minimum_baseline_windows=10,
        )
    )
    assert result.status == SignalStatus.UNAVAILABLE
    assert result.error_code == SignalErrorCode.DEPENDENCY_UNAVAILABLE
    assert result.points == 0.0
    assert "Insufficient baseline windows" in result.explanation


def test_trend_conflicting_counts_are_rejected() -> None:
    result = adapt_trend_context(
        TrendSnapshot(
            status=SignalStatus.AVAILABLE,
            baseline_window_count=20,
            target_window_count=5,
            anomalous_window_count=6,
            minimum_baseline_windows=10,
        )
    )
    assert result.status == SignalStatus.INVALID
    assert result.error_code == SignalErrorCode.CONFLICTING_OUTPUT
    assert result.points == 0.0


def test_trend_review_context_has_zero_points() -> None:
    result = adapt_trend_context(
        TrendSnapshot(
            status=SignalStatus.AVAILABLE,
            subject_ref="trend-window",
            baseline_window_count=20,
            target_window_count=10,
            anomalous_window_count=9,
            minimum_baseline_windows=10,
            threshold_percentile=90.0,
        )
    )
    assert result.status == SignalStatus.AVAILABLE
    assert result.observed_indicator == "ANOMALOUS_WINDOW_SHARE"
    assert result.points == 0.0
    assert result.cap == 0.0
    assert "not a calibrated anomaly probability" in result.reasons[0].message
    assert "not executed" in result.explanation
