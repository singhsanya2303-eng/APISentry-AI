
import pytest

from app.services.http_method_anomaly_service import (
    analyze_http_method_frequency,
)


def test_detects_rare_method_in_sufficient_baseline():
    events = [
        {"client_ip": "10.0.0.1", "method": "GET"}
        for _ in range(19)
    ]
    events.append({"client_ip": "10.0.0.1", "method": "DELETE"})

    results = analyze_http_method_frequency(events)

    delete_result = next(
        result for result in results
        if result["http_method"] == "DELETE"
    )

    assert delete_result["is_anomaly"] is True
    assert delete_result["reason"] == "rare_http_method"
    assert delete_result["method_frequency"] == pytest.approx(0.05)


def test_common_method_is_not_anomaly():
    events = [
        {"client_ip": "10.0.0.1", "method": "GET"}
        for _ in range(20)
    ]

    results = analyze_http_method_frequency(events)

    assert len(results) == 1
    assert results[0]["is_anomaly"] is False


def test_insufficient_baseline_does_not_flag_anomaly():
    events = [
        {"client_ip": "10.0.0.1", "method": "GET"},
        {"client_ip": "10.0.0.1", "method": "DELETE"},
    ]

    results = analyze_http_method_frequency(events)

    assert all(not result["is_anomaly"] for result in results)
    assert all(
        result["reason"] == "insufficient_baseline_data"
        for result in results
    )


def test_method_names_are_normalized():
    events = [
        {"client_ip": "10.0.0.1", "method": "get"}
        for _ in range(20)
    ]

    results = analyze_http_method_frequency(events)

    assert results[0]["http_method"] == "GET"


def test_missing_client_ip_and_method_are_ignored():
    events = [
        {"client_ip": None, "method": "GET"},
        {"client_ip": "10.0.0.1", "method": None},
        {"client_ip": " ", "method": "POST"},
        {"client_ip": "10.0.0.1", "method": "  "},
    ]

    assert analyze_http_method_frequency(events) == []


def test_clients_are_analyzed_separately():
    events = [
        {"client_ip": "10.0.0.1", "method": "GET"}
        for _ in range(20)
    ]
    events.append({"client_ip": "10.0.0.2", "method": "DELETE"})

    results = analyze_http_method_frequency(events)

    second_client = [
        result for result in results
        if result["client_ip"] == "10.0.0.2"
    ]

    assert len(second_client) == 1
    assert second_client[0]["is_anomaly"] is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_baseline_requests": 0},
        {"min_method_count": 0},
        {"max_method_frequency": -0.1},
        {"max_method_frequency": 1.1},
    ],
)
def test_invalid_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        analyze_http_method_frequency([], **kwargs)


def test_supports_event_objects():
    class Event:
        client_ip = "10.0.0.1"
        method = "GET"

    results = analyze_http_method_frequency([Event()])

    assert results[0]["http_method"] == "GET"
