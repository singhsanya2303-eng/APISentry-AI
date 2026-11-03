
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.services.traffic_aggregation_service import aggregate_traffic_logs


def make_log(second, request_id, client_ip, status_code, response_time, method="GET"):
    return SimpleNamespace(
        request_id=request_id,
        timestamp=datetime(2026, 1, 1, 12, 0, second, tzinfo=timezone.utc),
        client_ip=client_ip,
        status_code=status_code,
        response_time_ms=response_time,
        method=method,
    )


def test_aggregates_requests_in_same_ten_second_window():
    logs = [
        make_log(1, "r1", "10.0.0.1", 200, 100),
        make_log(5, "r2", "10.0.0.1", 404, 200, "POST"),
        make_log(9, "r3", "10.0.0.2", 500, 300),
    ]

    result = aggregate_traffic_logs(logs)

    assert len(result) == 1
    assert result[0]["request_count"] == 3
    assert result[0]["unique_client_count"] == 2
    assert result[0]["http_2xx_count"] == 1
    assert result[0]["http_4xx_count"] == 1
    assert result[0]["http_5xx_count"] == 1
    assert result[0]["mean_response_time_ms"] == 200
    assert result[0]["max_response_time_ms"] == 300
    assert result[0]["http_method_counts"] == {"GET": 2, "POST": 1}


def test_splits_requests_at_ten_second_boundary():
    logs = [
        make_log(9, "r1", "10.0.0.1", 200, 100),
        make_log(10, "r2", "10.0.0.1", 200, 150),
    ]

    result = aggregate_traffic_logs(logs)

    assert len(result) == 2
    assert [item["request_count"] for item in result] == [1, 1]


def test_empty_input_returns_empty_list():
    assert aggregate_traffic_logs([]) == []


def test_rejects_nonpositive_window_size():
    with pytest.raises(ValueError):
        aggregate_traffic_logs([], window_seconds=0)


def test_skips_logs_without_timestamp():
    log = SimpleNamespace(timestamp=None)

    assert aggregate_traffic_logs([log]) == []
