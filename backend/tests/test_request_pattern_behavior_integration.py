"""Integration tests for request-pattern review signals in behavior risk analysis."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services import behavior_analysis_service as service
from app.schemas.behavior import RiskLevel


def _log(request_id, client_ip, method, path, timestamp=None):
    return SimpleNamespace(
        request_id=request_id,
        client_ip=client_ip,
        method=method,
        path=path,
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=timezone.utc),
        status_code=200,
        query_params=None,
        user_agent="integration-test-agent",
    )


def _sample_logs(client_ip="203.0.113.10"):
    return [
        _log("req-1", client_ip, "GET", "/items"),
        _log("req-2", client_ip, "GET", "/items"),
        _log("req-3", client_ip, "GET", "/items"),
        _log("req-4", client_ip, "DELETE", "/admin"),
    ]


def _risk_result(client_ip, score):
    """Return a risk-result object compatible with the service."""
    return SimpleNamespace(
        client_ip=client_ip,
        risk_score=score,
        risk_level=RiskLevel.LOW,
        risk_factors=[],
        explanation="Test risk result.",
    )

def test_request_pattern_helper_counts_unique_clients_once():
    logs = _sample_logs()
    with patch(
        "app.services.request_pattern_anomaly_service.analyze_http_method_frequency",
        return_value=[{"client_ip": "203.0.113.10", "is_anomaly": True}],
    ), patch(
        "app.services.request_pattern_anomaly_service.analyze_request_path_frequency",
        return_value=[{"client_ip": "203.0.113.10", "is_anomaly": True}],
    ):
        assert service._count_request_pattern_review_clients(logs) == 1


def test_request_pattern_helper_returns_zero_for_empty_logs():
    assert service._count_request_pattern_review_clients([]) == 0


def test_request_pattern_review_is_reported_in_summary_without_changing_risk_scores(monkeypatch):
    logs = _sample_logs()
    monkeypatch.setattr(service, "get_traffic_logs", lambda **kwargs: logs)
    monkeypatch.setattr(service, "_derive_signals_from_logs", lambda logs, existing_signals: {})
    monkeypatch.setattr(service, "_count_user_agent_review_clients", lambda logs: 0)
    monkeypatch.setattr(service, "_count_request_pattern_review_clients", lambda logs: 1)

    class FakeRiskScorer:
        def __init__(self, config=None):
            pass

        def score_features(self, features):
            return _risk_result(features.client_ip, 12)

    monkeypatch.setattr(service, "RiskScorer", FakeRiskScorer)

    result = service.analyze_traffic_for_behavior_risk()

    assert "HTTP-method/request-path review flags were found for 1 client(s)" in result.summary
    assert result.total_clients == 1
    assert result.results[0].risk_score == 12


def test_caller_supplied_signals_skip_automatic_review_detectors(monkeypatch):
    logs = _sample_logs()
    monkeypatch.setattr(service, "get_traffic_logs", lambda **kwargs: logs)

    def should_not_run(*args, **kwargs):
        pytest.fail("Automatic detector should not run when signals_map is supplied")

    monkeypatch.setattr(service, "_derive_signals_from_logs", should_not_run)
    monkeypatch.setattr(service, "_count_user_agent_review_clients", should_not_run)
    monkeypatch.setattr(service, "_count_request_pattern_review_clients", should_not_run)

    class FakeRiskScorer:
        def __init__(self, config=None):
            pass

        def score_features(self, features):
            return _risk_result(features.client_ip, 0)

    monkeypatch.setattr(service, "RiskScorer", FakeRiskScorer)

    caller_signals = {
        "req-1": {
            "detection_source": "manual",
            "detection_verdict": "reviewed",
        }
    }
    result = service.analyze_traffic_for_behavior_risk(signals_map=caller_signals)
    assert result.total_clients == 1


def test_request_pattern_helper_handles_malformed_logs():
    malformed = SimpleNamespace(request_id=None, path=None)
    with patch(
        "app.services.request_pattern_anomaly_service.analyze_http_method_frequency",
        return_value=[],
    ), patch(
        "app.services.request_pattern_anomaly_service.analyze_request_path_frequency",
        return_value=[],
    ):
        assert service._count_request_pattern_review_clients([malformed]) == 0
