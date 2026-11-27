"""False-positive controls, determinism and privacy tests for MW2."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.schemas.advanced_detection_signals import (
    AdvancedSignalName,
    BehaviorSnapshot,
    CredentialSnapshot,
)
from app.schemas.unified_risk_assessment import SignalStatus
from app.services.advanced_detection.advisory_orchestrator import (
    build_advisory_envelope,
    orchestrate,
)


def _ref(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mw2-fp-{seed}"))


def _keys(value):
    if isinstance(value, dict):
        result = set(value)
        for child in value.values():
            result |= _keys(child)
        return result
    if isinstance(value, list):
        result = set()
        for child in value:
            result |= _keys(child)
        return result
    return set()


def test_single_weak_behaviour_signal_does_not_become_suspicious() -> None:
    result = build_advisory_envelope(
        {
            "behavior": {
                "status": SignalStatus.AVAILABLE.value,
                "request_count": 55,
            }
        }
    ).signals[0]

    assert result.points == 2.5
    assert result.severity.value == "LOW"
    assert "Fewer than two indicators" in (result.coverage_note or "")
    assert "not proof of automation or malice" in result.reasons[0].message


def test_conflicting_behaviour_label_is_retained_as_context() -> None:
    result = build_advisory_envelope(
        {
            "behavior": {
                "status": SignalStatus.AVAILABLE.value,
                "request_count": 99,
                "classification": "automation_benign",
                "bot_risk_score": 1.0,
                "burst_count": 5,
            }
        }
    ).signals[0]

    assert result.points == 5.0
    assert "automation_benign" in result.explanation
    assert "not added" in result.explanation
    assert result.severity.value == "LOW"


def test_shared_ip_is_not_used_to_escalate_credential_review() -> None:
    result = build_advisory_envelope(
        {
            "credential": CredentialSnapshot(
                status=SignalStatus.AVAILABLE,
                shared_ip_failure_groups=10,
                failure_count=1,
            )
        }
    ).signals[1]

    assert result.points == 0.0
    assert "Shared-IP" in (result.coverage_note or "")
    assert "not used against unrelated actors" in (result.coverage_note or "")


def test_all_signals_respect_their_caps_and_have_no_combined_score() -> None:
    envelope = orchestrate(
        {
            "subject_ref": "cap-check",
            "behavior": {
                "status": SignalStatus.AVAILABLE.value,
                "request_count": 1000,
                "dominant_path_share": 1.0,
                "burst_count": 100,
                "sequence_repeat_count": 100,
                "behavior_change_flags": ["a"],
                "coordinated_group_count": 100,
                "client_count": 100,
            },
            "credential": {
                "status": SignalStatus.AVAILABLE.value,
                "failure_count": 100,
                "distinct_account_keys": 100,
                "success_after_failure_count": 100,
            },
            "api_abuse": {
                "status": SignalStatus.AVAILABLE.value,
                "request_count": 1000,
                "peak_requests_per_window": 1000,
                "burst_count": 100,
                "error_4xx_count": 100,
                "error_5xx_count": 100,
                "distinct_method_count": 9,
                "rare_method_count": 9,
                "scraping_path_repeat_count": 100,
                "enumeration_path_count": 100,
                "sequential_object_count": 100,
                "distinct_path_count": 100,
            },
            "payload": {
                "status": SignalStatus.AVAILABLE.value,
                "labels": ["anomalous"] * 50,
            },
            "attribution": {
                "status": SignalStatus.AVAILABLE.value,
                "shared_ip": True,
            },
            "trend": {
                "status": SignalStatus.AVAILABLE.value,
                "baseline_window_count": 50,
                "target_window_count": 10,
                "anomalous_window_count": 10,
            },
        }
    )

    expected_caps = {
        AdvancedSignalName.COORDINATED_BEHAVIOR: 10.0,
        AdvancedSignalName.CREDENTIAL_ABUSE: 15.0,
        AdvancedSignalName.API_ABUSE: 15.0,
        AdvancedSignalName.ENUMERATION_REVIEW: 5.0,
        AdvancedSignalName.PAYLOAD_CONTEXT: 10.0,
        AdvancedSignalName.ATTRIBUTION_QUALITY: 0.0,
        AdvancedSignalName.TREND_CONTEXT: 0.0,
    }
    for signal in envelope.advanced_envelope.signals:
        assert signal.points <= expected_caps[signal.signal]
        assert signal.cap == expected_caps[signal.signal]
        assert signal.advisory_only is True

    dumped = envelope.model_dump()
    forbidden_keys = {
        "risk_score",
        "combined_score",
        "enforcement",
        "block",
        "throttle",
        "policy_id",
        "decision_score",
        "low_margin",
        "payload_echo",
    }
    assert not (_keys(dumped) & forbidden_keys)
    assert "No combined score" in envelope.advisory_notice


def test_raw_identifiers_and_secrets_are_not_emitted() -> None:
    opaque = _ref("evidence")
    envelope = build_advisory_envelope(
        {
            "behavior": BehaviorSnapshot(
                status=SignalStatus.AVAILABLE,
                subject_ref="opaque-subject",
                evidence_refs=[opaque],
                request_count=60,
            )
        }
    )
    serialized = envelope.model_dump_json()

    assert opaque in serialized
    for forbidden in (
        "Bearer ",
        "cookie=",
        "password=",
        "Authorization:",
        "raw-request-id",
        "decision_score",
        "low_margin",
        "payload_echo",
    ):
        assert forbidden not in serialized


def test_repeated_execution_is_byte_for_byte_deterministic() -> None:
    snapshots = {
        "subject_ref": "deterministic",
        "behavior": {
            "status": SignalStatus.AVAILABLE.value,
            "request_count": 60,
            "burst_count": 3,
            "evidence_refs": [_ref("det")],
        },
        "credential": {
            "status": SignalStatus.AVAILABLE.value,
            "failure_count": 5,
            "distinct_account_keys": 3,
        },
        "trend": {
            "status": SignalStatus.AVAILABLE.value,
            "baseline_window_count": 20,
            "target_window_count": 10,
            "anomalous_window_count": 9,
        },
    }
    first = build_advisory_envelope(snapshots).model_dump_json(indent=2)
    second = build_advisory_envelope(snapshots).model_dump_json(indent=2)

    assert first == second


def test_mw1_object_is_unchanged_and_advanced_points_are_not_added() -> None:
    mw1 = SimpleNamespace(risk_score=88.0, severity="CRITICAL")
    envelope = build_advisory_envelope(
        {
            "api_abuse": {
                "status": SignalStatus.AVAILABLE.value,
                "request_count": 100,
                "peak_requests_per_window": 100,
            }
        }
    )
    result = orchestrate({"api_abuse": {"status": SignalStatus.MISSING.value}}, mw1)

    assert result.unified_assessment is mw1
    assert mw1.risk_score == 88.0
    assert mw1.severity == "CRITICAL"
    assert envelope.signals[2].points > 0.0
    assert result.advanced_envelope.signals[2].points == 0.0
