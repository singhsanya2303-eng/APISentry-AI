"""Focused tests for User-Agent frequency anomaly detection."""

import pytest

from app.services.user_agent_anomaly_service import analyze_user_agent_frequency


def test_flags_non_baseline_user_agent_when_baseline_is_sufficient():
    events = [
        {"client_ip": "192.0.2.10", "user_agent": "Browser-A"},
        {"client_ip": "192.0.2.10", "user_agent": "Browser-A"},
        {"client_ip": "192.0.2.10", "user_agent": "Browser-A"},
        {"client_ip": "192.0.2.10", "user_agent": "Browser-B"},
    ]

    results = analyze_user_agent_frequency(events, min_baseline_requests=3)

    baseline = next(r for r in results if r["user_agent"] == "Browser-A")
    different = next(r for r in results if r["user_agent"] == "Browser-B")

    assert baseline["is_baseline_user_agent"] is True
    assert baseline["is_anomaly"] is False
    assert baseline["baseline_request_count"] == 3

    assert different["is_baseline_user_agent"] is False
    assert different["is_anomaly"] is True
    assert different["reason"] == "user_agent_differs_from_baseline"


def test_does_not_flag_anomaly_when_baseline_is_insufficient():
    events = [
        {"client_ip": "192.0.2.11", "user_agent": "Browser-A"},
        {"client_ip": "192.0.2.11", "user_agent": "Browser-B"},
    ]

    results = analyze_user_agent_frequency(events, min_baseline_requests=3)

    assert results
    assert all(r["is_anomaly"] is False for r in results)
    assert all(r["reason"] == "insufficient_baseline_data" for r in results)


def test_ignores_events_without_usable_ip_or_user_agent():
    events = [
        {"client_ip": "", "user_agent": "Browser-A"},
        {"client_ip": "192.0.2.12", "user_agent": "   "},
        {"client_ip": None, "user_agent": "Browser-B"},
        {"client_ip": "192.0.2.12", "user_agent": None},
        None,
    ]

    assert analyze_user_agent_frequency(events) == []


def test_accepts_event_objects_as_well_as_dictionaries():
    class Event:
        def __init__(self, client_ip, user_agent):
            self.client_ip = client_ip
            self.user_agent = user_agent

    events = [
        Event("192.0.2.13", "Browser-A"),
        Event("192.0.2.13", "Browser-A"),
        Event("192.0.2.13", "Browser-A"),
        Event("192.0.2.13", "Browser-B"),
    ]

    results = analyze_user_agent_frequency(events, min_baseline_requests=3)

    assert next(r for r in results if r["user_agent"] == "Browser-B")["is_anomaly"] is True


@pytest.mark.parametrize("invalid_value", [0, -1, True, 1.5, "3", None])
def test_rejects_invalid_minimum_baseline_request_count(invalid_value):
    with pytest.raises(ValueError, match="min_baseline_requests must be a positive integer"):
        analyze_user_agent_frequency([], min_baseline_requests=invalid_value)
