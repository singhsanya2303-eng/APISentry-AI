
"""Extract per-client API behavior frequency features."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.schemas.behavior import BehaviorEvent


def _utc_timestamp(value: datetime) -> datetime:
    """Normalize timestamps to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def extract_user_behavior_features(
    events: List[BehaviorEvent],
) -> List[Dict[str, Any]]:
    """Calculate method and endpoint frequencies for each client IP.

    Events without a client IP are excluded because this service attributes
    behavioral profiles by client IP and never fabricates identity.
    """
    grouped: Dict[str, List[BehaviorEvent]] = {}

    for event in events:
        if not event or not event.client_ip:
            continue

        client_ip = event.client_ip.strip()
        if not client_ip:
            continue

        grouped.setdefault(client_ip, []).append(event)

    results: List[Dict[str, Any]] = []

    for client_ip in sorted(grouped):
        client_events = grouped[client_ip]

        method_counts = Counter(
            event.method.strip().upper()
            for event in client_events
            if event.method and event.method.strip()
        )

        endpoint_counts = Counter(
            event.normalized_endpoint.strip()
            for event in client_events
            if event.normalized_endpoint
            and event.normalized_endpoint.strip()
        )

        timestamps = [
            _utc_timestamp(event.timestamp)
            for event in client_events
            if event.timestamp is not None
        ]

        results.append(
            {
                "client_ip": client_ip,
                "actor_id": next(
                    (
                        event.actor_id
                        for event in client_events
                        if event.actor_id
                    ),
                    None,
                ),
                "total_requests": len(client_events),
                "http_method_counts": dict(sorted(method_counts.items())),
                "endpoint_frequency": dict(sorted(endpoint_counts.items())),
                "unique_http_methods": len(method_counts),
                "unique_endpoints": len(endpoint_counts),
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
            }
        )

    return results
