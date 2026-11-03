
from datetime import datetime, timedelta, timezone

import pytest

from app.services.geo_velocity_anomaly_service import (
    analyze_geo_velocity,
    haversine_distance_km,
)


def make_event(actor_id, timestamp, latitude, longitude):
    return {
        "actor_id": actor_id,
        "timestamp": timestamp,
        "latitude": latitude,
        "longitude": longitude,
    }


def test_haversine_distance_is_zero_for_same_location():
    assert haversine_distance_km(28.6139, 77.2090, 28.6139, 77.2090) == 0


def test_haversine_distance_calculates_delhi_to_mumbai():
    distance = haversine_distance_km(
        28.6139, 77.2090, 19.0760, 72.8777
    )
    assert 1100 < distance < 1200


def test_flags_suspicious_travel_between_distant_locations():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event("user-1", start, 28.6139, 77.2090),
        make_event(
            "user-1",
            start + timedelta(minutes=10),
            51.5072,
            -0.1276,
        ),
    ]

    result = analyze_geo_velocity(events)

    assert len(result) == 1
    assert result[0]["is_anomaly"] is True
    assert result[0]["reason"] == "impossible_travel_speed"
    assert result[0]["estimated_speed_kmh"] > 900


def test_does_not_flag_nearby_locations_over_sufficient_time():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event("user-1", start, 28.6139, 77.2090),
        make_event(
            "user-1",
            start + timedelta(hours=2),
            28.7041,
            77.1025,
        ),
    ]

    result = analyze_geo_velocity(events)

    assert len(result) == 1
    assert result[0]["is_anomaly"] is False


def test_compares_events_separately_for_each_actor():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event("user-2", start, 28.6139, 77.2090),
        make_event(
            "user-2",
            start + timedelta(minutes=10),
            51.5072,
            -0.1276,
        ),
        make_event("user-1", start, 28.6139, 77.2090),
        make_event(
            "user-1",
            start + timedelta(minutes=10),
            28.7041,
            77.1025,
        ),
    ]

    result = analyze_geo_velocity(events)

    assert len(result) == 2
    by_actor = {item["actor_id"]: item for item in result}
    assert by_actor["user-2"]["is_anomaly"] is True
    assert by_actor["user-1"]["is_anomaly"] is False


def test_ignores_events_without_identity_or_valid_coordinates():
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event(None, timestamp, 28.0, 77.0),
        make_event("user-1", timestamp, 95.0, 77.0),
        make_event("user-1", timestamp, 28.0, None),
        {"actor_id": "user-1", "timestamp": timestamp},
    ]

    assert analyze_geo_velocity(events) == []


def test_ignores_pairs_with_equal_timestamps():
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        make_event("user-1", timestamp, 28.6139, 77.2090),
        make_event("user-1", timestamp, 51.5072, -0.1276),
    ]

    assert analyze_geo_velocity(events) == []


def test_sorts_events_by_timestamp_before_comparison():
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            "user-1",
            start + timedelta(minutes=10),
            51.5072,
            -0.1276,
        ),
        make_event("user-1", start, 28.6139, 77.2090),
    ]

    result = analyze_geo_velocity(events)

    assert len(result) == 1
    assert result[0]["is_anomaly"] is True
    assert result[0]["elapsed_seconds"] == 600


@pytest.mark.parametrize("max_speed", [0, -1, True, "900"])
def test_rejects_invalid_speed_threshold(max_speed):
    with pytest.raises(ValueError):
        analyze_geo_velocity([], max_speed_kmh=max_speed)


@pytest.mark.parametrize("min_distance", [-1, True, "100"])
def test_rejects_invalid_minimum_distance(min_distance):
    with pytest.raises(ValueError):
        analyze_geo_velocity([], min_distance_km=min_distance)


def test_accepts_naive_timestamps_as_utc():
    start = datetime(2026, 1, 1, 10, 0)
    events = [
        make_event("user-1", start, 28.6139, 77.2090),
        make_event(
            "user-1",
            start + timedelta(minutes=10),
            51.5072,
            -0.1276,
        ),
    ]

    result = analyze_geo_velocity(events)

    assert result[0]["previous_timestamp"].tzinfo == timezone.utc
    assert result[0]["is_anomaly"] is True


def test_accepts_object_events():
    class Event:
        def __init__(self, actor_id, timestamp, latitude, longitude):
            self.actor_id = actor_id
            self.timestamp = timestamp
            self.latitude = latitude
            self.longitude = longitude

    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        Event("user-1", start, 28.6139, 77.2090),
        Event(
            "user-1",
            start + timedelta(minutes=10),
            51.5072,
            -0.1276,
        ),
    ]

    result = analyze_geo_velocity(events)

    assert len(result) == 1
    assert result[0]["is_anomaly"] is True
