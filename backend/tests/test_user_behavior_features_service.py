
from datetime import datetime, timezone

from app.schemas.behavior import BehaviorEvent
from app.services.user_behavior_features_service import (
    extract_user_behavior_features,
)


def make_event(
    request_id,
    client_ip,
    method,
    endpoint,
    actor_id=None,
):
    return BehaviorEvent(
        request_id=request_id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        client_ip=client_ip,
        actor_id=actor_id,
        method=method,
        path=endpoint,
        normalized_endpoint=endpoint,
        status_code=200,
    )


def test_extracts_method_and_endpoint_frequencies():
    events = [
        make_event("1", "192.0.2.10", "get", "/users/{id}"),
        make_event("2", "192.0.2.10", "GET", "/users/{id}"),
        make_event("3", "192.0.2.10", "POST", "/users"),
    ]

    results = extract_user_behavior_features(events)

    assert len(results) == 1
    profile = results[0]

    assert profile["total_requests"] == 3
    assert profile["http_method_counts"] == {"GET": 2, "POST": 1}
    assert profile["endpoint_frequency"] == {
        "/users": 1,
        "/users/{id}": 2,
    }
    assert profile["unique_http_methods"] == 2
    assert profile["unique_endpoints"] == 2


def test_groups_events_by_client_ip():
    events = [
        make_event("1", "192.0.2.10", "GET", "/users"),
        make_event("2", "192.0.2.11", "POST", "/orders"),
    ]

    results = extract_user_behavior_features(events)

    assert len(results) == 2
    assert [item["client_ip"] for item in results] == [
        "192.0.2.10",
        "192.0.2.11",
    ]


def test_skips_events_without_client_ip():
    events = [
        make_event("1", None, "GET", "/users"),
        make_event("2", " ", "POST", "/orders"),
    ]

    assert extract_user_behavior_features(events) == []


def test_empty_events_return_empty_list():
    assert extract_user_behavior_features([]) == []


def test_actor_id_is_optional():
    events = [
        make_event(
            "1",
            "192.0.2.10",
            "GET",
            "/users",
            actor_id="user-123",
        )
    ]

    result = extract_user_behavior_features(events)

    assert result[0]["actor_id"] == "user-123"
