
"""Detect potentially impossible travel between API request locations.

This service accepts coordinates supplied by an upstream geolocation source.
It does not perform IP-to-location lookups itself.
"""

from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt
from typing import Any, Dict, List, Optional


EARTH_RADIUS_KM = 6371.0088


def _utc_timestamp(value: datetime) -> datetime:
    """Normalize a datetime to UTC; interpret naive values as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _get_value(event: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def _valid_coordinate(value: Any, minimum: float, maximum: float) -> bool:
    """Return whether a coordinate is numeric, finite, and in range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return minimum <= value <= maximum


def haversine_distance_km(
    latitude1: float,
    longitude1: float,
    latitude2: float,
    longitude2: float,
) -> float:
    """Calculate great-circle distance between two geographic coordinates."""
    for latitude in (latitude1, latitude2):
        if not _valid_coordinate(latitude, -90, 90):
            raise ValueError("Latitude must be between -90 and 90.")

    for longitude in (longitude1, longitude2):
        if not _valid_coordinate(longitude, -180, 180):
            raise ValueError("Longitude must be between -180 and 180.")

    lat1 = radians(latitude1)
    lat2 = radians(latitude2)
    delta_lat = radians(latitude2 - latitude1)
    delta_lon = radians(longitude2 - longitude1)

    haversine = (
        sin(delta_lat / 2) ** 2
        + cos(lat1) * cos(lat2) * sin(delta_lon / 2) ** 2
    )
    # Protect against floating-point rounding outside [0, 1].
    haversine = min(1.0, max(0.0, haversine))

    return 2 * EARTH_RADIUS_KM * asin(sqrt(haversine))


def analyze_geo_velocity(
    events: List[Any],
    max_speed_kmh: float = 900.0,
    min_distance_km: float = 100.0,
) -> List[Dict[str, Any]]:
    """Flag consecutive location changes that exceed a configured speed.

    Each event must provide:
      - actor_id: stable user identity
      - timestamp: datetime
      - latitude and longitude: numeric coordinates

    Events missing identity, timestamp, or valid coordinates are ignored.
    Only consecutive usable events for the same actor are compared.

    The speed threshold is a configurable heuristic, not proof of an attack.
    """
    if not isinstance(max_speed_kmh, (int, float)) or isinstance(
        max_speed_kmh, bool
    ):
        raise ValueError("max_speed_kmh must be a positive number.")
    if max_speed_kmh <= 0:
        raise ValueError("max_speed_kmh must be a positive number.")

    if not isinstance(min_distance_km, (int, float)) or isinstance(
        min_distance_km, bool
    ):
        raise ValueError("min_distance_km must be a non-negative number.")
    if min_distance_km < 0:
        raise ValueError("min_distance_km must be a non-negative number.")

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for event in events:
        actor_id = _get_value(event, "actor_id")
        timestamp = _get_value(event, "timestamp")
        latitude = _get_value(event, "latitude")
        longitude = _get_value(event, "longitude")

        if actor_id is None or not str(actor_id).strip():
            continue
        if not isinstance(timestamp, datetime):
            continue
        if not _valid_coordinate(latitude, -90, 90):
            continue
        if not _valid_coordinate(longitude, -180, 180):
            continue

        grouped.setdefault(str(actor_id).strip(), []).append(
            {
                "actor_id": str(actor_id).strip(),
                "timestamp": _utc_timestamp(timestamp),
                "latitude": float(latitude),
                "longitude": float(longitude),
            }
        )

    results: List[Dict[str, Any]] = []

    for actor_id in sorted(grouped):
        actor_events = sorted(
            grouped[actor_id], key=lambda item: item["timestamp"]
        )

        for previous, current in zip(actor_events, actor_events[1:]):
            elapsed_seconds = (
                current["timestamp"] - previous["timestamp"]
            ).total_seconds()

            # Equal timestamps or reversed chronology cannot establish speed.
            if elapsed_seconds <= 0:
                continue

            distance_km = haversine_distance_km(
                previous["latitude"],
                previous["longitude"],
                current["latitude"],
                current["longitude"],
            )
            elapsed_hours = elapsed_seconds / 3600
            speed_kmh = distance_km / elapsed_hours

            suspicious = (
                distance_km >= min_distance_km
                and speed_kmh > max_speed_kmh
            )

            results.append(
                {
                    "actor_id": actor_id,
                    "previous_timestamp": previous["timestamp"],
                    "current_timestamp": current["timestamp"],
                    "distance_km": round(distance_km, 3),
                    "elapsed_seconds": round(elapsed_seconds, 3),
                    "estimated_speed_kmh": round(speed_kmh, 3),
                    "is_anomaly": suspicious,
                    "reason": (
                        "impossible_travel_speed"
                        if suspicious
                        else "travel_speed_within_threshold"
                    ),
                }
            )

    return results
