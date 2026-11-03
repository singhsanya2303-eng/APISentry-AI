
import pytest

from app.services.request_path_anomaly_service import (
    analyze_request_path_frequency,
)


def test_detects_rare_normalized_endpoint():
    events = [
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/products",
        }
        for _ in range(19)
    ]
    events.append(
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/admin",
        }
    )

    results = analyze_request_path_frequency(events)

    rare_path = next(
        result for result in results
        if result["normalized_endpoint"] == "/api/admin"
    )

    assert rare_path["is_anomaly"] is True
    assert rare_path["reason"] == "rare_normalized_endpoint"
    assert rare_path["path_frequency"] == pytest.approx(0.05)


def test_common_endpoint_is_not_anomaly():
    events = [
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/products",
        }
        for _ in range(20)
    ]

    results = analyze_request_path_frequency(events)

    assert len(results) == 1
    assert results[0]["is_anomaly"] is False


def test_insufficient_baseline_does_not_flag_anomaly():
    events = [
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/products",
        },
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/admin",
        },
    ]

    results = analyze_request_path_frequency(events)

    assert all(not result["is_anomaly"] for result in results)
    assert all(
        result["reason"] == "insufficient_baseline_data"
        for result in results
    )


def test_ignores_missing_client_ip_and_endpoint():
    events = [
        {"client_ip": None, "normalized_endpoint": "/api/products"},
        {"client_ip": "10.0.0.1", "normalized_endpoint": None},
        {"client_ip": " ", "normalized_endpoint": "/api/products"},
        {"client_ip": "10.0.0.1", "normalized_endpoint": "  "},
    ]

    assert analyze_request_path_frequency(events) == []


def test_keeps_clients_separate():
    events = [
        {
            "client_ip": "10.0.0.1",
            "normalized_endpoint": "/api/products",
        }
        for _ in range(20)
    ]
    events.append(
        {
            "client_ip": "10.0.0.2",
            "normalized_endpoint": "/api/admin",
        }
    )

    results = analyze_request_path_frequency(events)

    client_two = [
        result for result in results
        if result["client_ip"] == "10.0.0.2"
    ]

    assert len(client_two) == 1
    assert client_two[0]["is_anomaly"] is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"min_baseline_requests": 0},
        {"max_path_frequency": -0.1},
        {"max_path_frequency": 1.1},
    ],
)
def test_rejects_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        analyze_request_path_frequency([], **kwargs)


def test_supports_event_objects():
    class Event:
        client_ip = "10.0.0.1"
        normalized_endpoint = "/api/products"

    results = analyze_request_path_frequency([Event()])

    assert results[0]["normalized_endpoint"] == "/api/products"
