import pytest

from app.services.request_pattern_anomaly_service import (
    analyze_http_method_frequency,
    analyze_request_path_frequency,
)


def _events(field, baseline, unusual, baseline_count=3):
    events = [
        {"client_ip": "10.0.0.1", field: baseline}
        for _ in range(baseline_count)
    ]
    events.append({"client_ip": "10.0.0.1", field: unusual})
    return events


def test_http_method_flags_rare_method_after_baseline():
    results = analyze_http_method_frequency(
        _events("method", "GET", "DELETE")
    )
    by_method = {item["http_method"]: item for item in results}

    assert by_method["GET"]["is_anomaly"] is False
    assert by_method["DELETE"]["is_anomaly"] is True
    assert by_method["DELETE"]["baseline_http_method"] == "GET"
    assert (
        by_method["DELETE"]["reason"]
        == "method_differs_from_baseline"
    )


def test_path_flags_rare_path_after_baseline():
    results = analyze_request_path_frequency(
        _events("path", "/api/products", "/api/admin")
    )
    by_path = {item["request_path"]: item for item in results}

    assert by_path["/api/products"]["is_anomaly"] is False
    assert by_path["/api/admin"]["is_anomaly"] is True
    assert (
        by_path["/api/admin"]["baseline_request_path"]
        == "/api/products"
    )


def test_insufficient_baseline_does_not_flag():
    results = analyze_http_method_frequency([
        {"client_ip": "10.0.0.1", "method": "GET"},
        {"client_ip": "10.0.0.1", "method": "DELETE"},
    ])

    assert all(item["is_anomaly"] is False for item in results)
    assert all(
        item["reason"] == "insufficient_baseline_data"
        for item in results
    )


@pytest.mark.parametrize(
    "analyzer,field",
    [
        (analyze_http_method_frequency, "method"),
        (analyze_request_path_frequency, "path"),
    ],
)
@pytest.mark.parametrize(
    "bad_value",
    [0, -1, True, 1.5, "3", None],
)
def test_invalid_minimum_baseline_raises(analyzer, field, bad_value):
    with pytest.raises(ValueError, match="positive integer"):
        analyzer([], min_baseline_requests=bad_value)


def test_invalid_events_are_ignored():
    results = analyze_http_method_frequency([
        None,
        {"client_ip": "", "method": "GET"},
        {"client_ip": "10.0.0.1", "method": ""},
        {"client_ip": "10.0.0.1", "method": "GET"},
    ])

    assert len(results) == 1
    assert results[0]["http_method"] == "GET"
    assert results[0]["is_anomaly"] is False