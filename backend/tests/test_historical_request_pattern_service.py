
from datetime import datetime, timedelta, timezone

import pytest

from app.services.historical_request_pattern_service import (
    analyze_historical_request_patterns,
    get_historical_window,
)


def make_event(client_ip, method="GET", path="/items", timestamp=None):
    return {
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "timestamp": timestamp or datetime.now(timezone.utc),
    }


def test_unseen_method_is_flagged_with_sufficient_history():
    history = [
        make_event("10.0.0.1", "GET", "/items")
        for _ in range(10)
    ]
    current = [make_event("10.0.0.1", "DELETE", "/items")]

    findings = analyze_historical_request_patterns(current, history)

    method_finding = next(
        item for item in findings
        if item["http_method"] == "DELETE"
    )
    assert method_finding["is_anomaly"] is True
    assert method_finding["reason"] == "unseen_historical_method"


def test_unseen_path_is_flagged_with_sufficient_history():
    history = [
        make_event("10.0.0.2", "GET", "/items")
        for _ in range(10)
    ]
    current = [make_event("10.0.0.2", "GET", "/admin")]

    findings = analyze_historical_request_patterns(current, history)

    path_finding = next(
        item for item in findings
        if item.get("request_path") == "/admin"
    )
    assert path_finding["is_anomaly"] is True
    assert path_finding["reason"] == "unseen_historical_path"


def test_insufficient_history_does_not_flag_anomaly():
    history = [
        make_event("10.0.0.3", "GET", "/items")
        for _ in range(9)
    ]
    current = [make_event("10.0.0.3", "DELETE", "/admin")]

    findings = analyze_historical_request_patterns(current, history)

    assert findings
    assert all(item["is_anomaly"] is False for item in findings)
    assert all(
        item["reason"] == "insufficient_historical_data"
        for item in findings
    )


def test_other_clients_history_is_not_used():
    history = [
        make_event("10.0.0.4", "GET", "/items")
        for _ in range(10)
    ]
    current = [make_event("10.0.0.5", "DELETE", "/admin")]

    findings = analyze_historical_request_patterns(current, history)

    assert findings
    assert all(item["is_anomaly"] is False for item in findings)
    assert all(
        item["reason"] == "insufficient_historical_data"
        for item in findings
    )


def test_historical_window_defaults_to_seven_days():
    end_time = datetime(2026, 10, 26, tzinfo=timezone.utc)

    start_time, actual_end = get_historical_window(end_time)

    assert actual_end == end_time
    assert actual_end - start_time == timedelta(days=7)


@pytest.mark.parametrize("days", [0, -1, True, 1.5])
def test_invalid_lookback_days_are_rejected(days):
    with pytest.raises(ValueError):
        get_historical_window(
            datetime.now(timezone.utc),
            lookback_days=days,
        )


@pytest.mark.parametrize("minimum", [0, -1, True, 1.5])
def test_invalid_minimum_history_is_rejected(minimum):
    with pytest.raises(ValueError):
        analyze_historical_request_patterns(
            current_events=[make_event("10.0.0.6")],
            historical_events=[],
            min_historical_requests=minimum,
        )
