"""Focused tests for the advisory unified risk assessment service."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.unified_risk_assessment import SignalErrorCode, SignalStatus
from app.services.unified_risk_assessment_service import (
    assess_risk,
    from_behavior_analysis_response,
    from_bot_detection_response,
    from_mitigation_decision,
    from_payload_classifier_response,
    from_rate_anomaly_result,
)


def _opaque_ref(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def _available(**fields: Any) -> dict[str, Any]:
    return {"status": SignalStatus.AVAILABLE.value, **fields}


def test_all_missing_signals_are_explicit_and_not_treated_as_clean() -> None:
    result = assess_risk({})

    assert result.risk_score == 0.0
    assert result.severity.value == "LOW"
    assert result.advisory_only is True
    assert result.coverage.signals_available == 0
    assert result.coverage.signals_missing == 6
    assert result.coverage.coverage_ratio == 0.0
    assert len(result.contributions) == 6
    assert {item.status for item in result.contributions} == {SignalStatus.MISSING}
    assert any(reason.code == "NO_POINTS_CONTRIBUTED" for reason in result.reasons)
    assert any("not available" in note for note in result.uncertainty_notes)


def test_bot_signal_contributes_capped_points_with_opaque_evidence() -> None:
    reference = _opaque_ref("mw1-bot-evidence")
    result = assess_risk(
        {
            "bot_detection": _available(
                bot_risk_score=80.0,
                classification="automation_suspicious",
                suspicious_automation_candidates=2,
                evidence_references=[reference],
                limits_truncated=True,
            )
        }
    )

    assert result.risk_score == 24.0
    assert result.severity.value == "LOW"
    contribution = next(
        item for item in result.contributions if item.signal.value == "bot_detection"
    )
    assert contribution.points == 24.0
    assert contribution.evidence_refs == [reference]
    assert contribution.source_module == "app.services.bot_detection_service"
    assert contribution.source_function == "analyze_traffic_for_bot_detection"
    assert any("truncated" in note for note in result.uncertainty_notes)


def test_payload_adapter_strips_decision_margin_and_uses_label_only() -> None:
    normalized = from_payload_classifier_response(
        {
            "artifact_sha256": "a" * 64,
            "results": [
                {
                    "index": 0,
                    "label": "anomalous",
                    "label_int": 1,
                    "decision_score": 4.7,
                    "decision_threshold": 0.0,
                    "score_type": "decision_score",
                    "payload_length": 12,
                    "low_margin": False,
                    "payload_echo": "secret-like-value",
                }
            ],
        }
    )

    assert "decision_score" not in normalized["results"][0]
    assert "payload_echo" not in normalized["results"][0]
    assert "score_type" not in normalized["results"][0]

    result = assess_risk({"payload_classifier": normalized})
    assert result.risk_score == 10.0
    assert result.severity.value == "LOW"
    contribution = next(
        item
        for item in result.contributions
        if item.signal.value == "payload_classifier"
    )
    assert "decision margin" in contribution.rationale.lower()
    assert contribution.source_confidence is None


def test_traffic_anomaly_maps_to_medium_and_keeps_confidence_as_provenance() -> None:
    result = assess_risk(
        {
            "traffic_anomaly": _available(
                verdict="suspicious_rate_anomaly",
                anomalous_request_count=12,
                source_confidence=0.83,
                window_seconds=60.0,
            )
        }
    )

    assert result.risk_score == 25.0
    assert result.severity.value == "MEDIUM"
    contribution = next(
        item
        for item in result.contributions
        if item.signal.value == "traffic_anomaly"
    )
    assert contribution.points == 25.0
    assert contribution.source_confidence == 0.83
    assert "provenance only" in contribution.rationale


def test_combined_signals_reach_the_upper_bound_without_arbitrary_extras() -> None:
    result = assess_risk(
        {
            "bot_detection": _available(
                bot_risk_score=100.0, classification="automation_suspicious"
            ),
            "behavior_risk": _available(
                risk_score=100.0, risk_level="CRITICAL", factor_names=["bola_activity"]
            ),
            "traffic_anomaly": _available(
                verdict="suspicious_rate_anomaly", anomalous_request_count=50
            ),
            "payload_classifier": _available(
                results=[{"index": 0, "label": "anomalous", "low_margin": False}]
            ),
            "request_pattern": _available(flags=["unusual_method_frequency"]),
            "mitigation_context": _available(decision="block", policy_version="v1"),
        }
    )

    assert result.raw_contribution_total == 100.0
    assert result.risk_score == 100.0
    assert result.clamp_applied is False
    assert result.severity.value == "CRITICAL"
    assert sum(item.points for item in result.contributions) == 100.0
    assert any(
        reason.code == "MITIGATION_ADVISORY_RECOMMENDATION_ONLY"
        for reason in result.reasons
    )


@pytest.mark.parametrize(
    "signals, expected_score, expected_severity",
    [
        ({"bot_detection": _available(bot_risk_score=83.0)}, 24.9, "LOW"),
        (
            {"traffic_anomaly": _available(
                verdict="suspicious_rate_anomaly", anomalous_request_count=1
            )},
            25.0,
            "MEDIUM",
        ),
        (
            {
                "bot_detection": _available(bot_risk_score=100.0),
                "behavior_risk": _available(risk_score=66.7, risk_level="HIGH"),
            },
            50.0,
            "HIGH",
        ),
        (
            {
                "bot_detection": _available(bot_risk_score=100.0),
                "behavior_risk": _available(risk_score=100.0, risk_level="CRITICAL"),
                "traffic_anomaly": _available(
                    verdict="suspicious_rate_anomaly", anomalous_request_count=1
                ),
            },
            85.0,
            "CRITICAL",
        ),
    ],
)
def test_score_boundaries_and_severity_mapping(
    signals: dict[str, Any], expected_score: float, expected_severity: str
) -> None:
    result = assess_risk(signals)

    assert result.risk_score == expected_score
    assert result.severity.value == expected_severity


def test_detector_timeout_is_contained_and_other_signals_still_score() -> None:
    result = assess_risk(
        {
            "bot_detection": {
                "status": SignalStatus.ERROR.value,
                "error_code": SignalErrorCode.DETECTOR_TIMEOUT.value,
            },
            "behavior_risk": _available(
                risk_score=100.0, risk_level="CRITICAL"
            ),
        }
    )

    assert result.risk_score == 30.0
    assert result.severity.value == "MEDIUM"
    assert result.coverage.signals_error == 1
    status = next(
        item for item in result.signal_statuses if item.signal.value == "bot_detection"
    )
    assert status.status == SignalStatus.ERROR
    assert status.error_code == SignalErrorCode.DETECTOR_TIMEOUT
    assert any("timeout" in reason.code.lower() for reason in result.reasons)


def test_out_of_range_signal_is_invalid_without_crashing_assessment() -> None:
    result = assess_risk(
        {"bot_detection": _available(bot_risk_score=150.0, classification="unknown")}
    )

    assert result.risk_score == 0.0
    assert result.coverage.signals_invalid == 1
    status = next(
        item for item in result.signal_statuses if item.signal.value == "bot_detection"
    )
    assert status.status == SignalStatus.INVALID
    assert status.error_code == SignalErrorCode.INVALID_OUTPUT


def test_malformed_signal_is_invalid_without_crashing_assessment() -> None:
    result = assess_risk({"payload_classifier": {"results": "not-a-list"}})

    assert result.risk_score == 0.0
    assert result.coverage.signals_invalid == 1
    assert any(
        reason.code.startswith("PAYLOAD_CLASSIFIER_INVALID")
        for reason in result.reasons
    )


def test_conflicting_fields_are_reported_and_severity_stays_consistent() -> None:
    result = assess_risk(
        {
            "bot_detection": _available(
                bot_risk_score=0.0, classification="automation_suspicious"
            ),
            "traffic_anomaly": _available(
                verdict="suspicious_rate_anomaly", anomalous_request_count=0
            ),
            "behavior_risk": _available(
                risk_score=10.0, risk_level="CRITICAL"
            ),
        }
    )

    codes = {reason.code for reason in result.reasons}
    assert "BOT_SCORE_CLASSIFICATION_CONFLICT" in codes
    assert "TRAFFIC_VERDICT_COUNT_CONFLICT" in codes
    assert "BEHAVIOR_SCORE_LEVEL_CONFLICT" in codes
    assert result.risk_score == 3.0
    assert result.severity.value == "LOW"
    assert "CONFLICTING_OUTPUT" not in {
        item.error_code.value for item in result.signal_statuses if item.error_code
    }


def test_low_margin_flag_does_not_change_payload_points() -> None:
    low = assess_risk(
        {
            "payload_classifier": _available(
                results=[{"index": 0, "label": "benign", "low_margin": True}]
            )
        }
    )
    normal = assess_risk(
        {
            "payload_classifier": _available(
                results=[{"index": 0, "label": "benign", "low_margin": False}]
            )
        }
    )

    assert low.risk_score == normal.risk_score == 0.0
    assert any(
        reason.code == "PAYLOAD_LOW_MARGIN_DESCRIPTIVE" for reason in low.reasons
    )
    assert not any(
        reason.code == "PAYLOAD_LOW_MARGIN_DESCRIPTIVE" for reason in normal.reasons
    )


def test_advisory_contract_has_no_enforcement_or_probability_fields() -> None:
    payload = assess_risk({}).model_dump()
    forbidden = {
        "probability",
        "confidence",
        "risk_probability",
        "action",
        "enforcement_action",
        "block",
        "throttle",
        "policy_written",
    }

    assert forbidden.isdisjoint(payload.keys())
    assert payload["advisory_only"] is True
    assert "does not block" in payload["advisory_notice"]


def test_top_level_malformed_input_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        assess_risk({"unexpected_field": 1})


def test_existing_response_adapters_extract_only_safe_fields() -> None:
    reference = _opaque_ref("adapter-evidence")
    bot = from_bot_detection_response(
        {
            "results": [
                {
                    "bot_risk_score": 70.0,
                    "classification": "automation_benign_candidate",
                    "evidence_references": [{"request_id": reference, "source": "rate"}],
                }
            ],
            "summary": {"suspicious_automation_candidates": 1},
            "limits": {"truncated": False},
        }
    )
    behavior = from_behavior_analysis_response(
        {
            "results": [
                {
                    "risk_score": 55.0,
                    "risk_level": "HIGH",
                    "factors": [{"factor_name": "rate_anomaly_activity"}],
                }
            ]
        }
    )
    traffic = from_rate_anomaly_result(
        {
            "verdict": "suspicious_rate_anomaly",
            "anomalous_request_count": 8,
            "evidences": [
                {"confidence_score": 0.75, "time_window_seconds": 60.0}
            ],
        }
    )
    mitigation = from_mitigation_decision(
        {"decision": "monitor", "policy_version": "policy-v3"}
    )

    assert bot["bot_risk_score"] == 70.0
    assert bot["evidence_references"] == [reference]
    assert behavior["risk_score"] == 55.0
    assert behavior["factor_names"] == ["rate_anomaly_activity"]
    assert traffic["source_confidence"] == 0.75
    assert mitigation["decision"] == "monitor"
    assert "request_ids" not in traffic
    assert "payload_echo" not in bot


def test_service_source_has_no_persistence_or_detector_execution_hooks() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "app/services/unified_risk_assessment_service.py"
    ).read_text(encoding="utf-8")

    assert "get_db" not in source
    assert "commit(" not in source
    assert "evaluate_and_persist_bot_detection" not in source
    assert "analyze_traffic_for_bot_detection(" not in source
