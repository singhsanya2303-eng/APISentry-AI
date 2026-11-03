
"""Historical per-client HTTP method and request-path baseline analysis."""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List


DEFAULT_LOOKBACK_DAYS = 7
DEFAULT_MIN_HISTORICAL_REQUESTS = 10


def _get_value(event: Any, field: str) -> Any:
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def analyze_historical_request_patterns(
    current_events: Iterable[Any],
    historical_events: Iterable[Any],
    min_historical_requests: int = DEFAULT_MIN_HISTORICAL_REQUESTS,
) -> List[Dict[str, Any]]:
    """Compare current methods and paths against each client's history.

    Historical events must be retrieved separately from current events.
    An anomaly is a review indicator, not proof of an attack.
    """
    if (
        isinstance(min_historical_requests, bool)
        or not isinstance(min_historical_requests, int)
        or min_historical_requests < 1
    ):
        raise ValueError("min_historical_requests must be a positive integer")

    history: Dict[str, List[Any]] = defaultdict(list)
    current: Dict[str, List[Any]] = defaultdict(list)

    def add_events(events: Iterable[Any], destination: Dict[str, List[Any]]) -> None:
        for event in events:
            if event is None:
                continue

            client_ip = _get_value(event, "client_ip")
            if not isinstance(client_ip, str) or not client_ip.strip():
                continue

            destination[client_ip.strip()].append(event)

    add_events(historical_events, history)
    add_events(current_events, current)

    findings: List[Dict[str, Any]] = []

    for client_ip in sorted(current):
        past_events = history.get(client_ip, [])
        enough_history = len(past_events) >= min_historical_requests

        for field, output_field in (
            ("method", "http_method"),
            ("path", "request_path"),
        ):
            historical_values = [
                _get_value(event, field).strip()
                for event in past_events
                if isinstance(_get_value(event, field), str)
                and _get_value(event, field).strip()
            ]
            current_counts = Counter(
                _get_value(event, field).strip()
                for event in current[client_ip]
                if isinstance(_get_value(event, field), str)
                and _get_value(event, field).strip()
            )

            baseline_counts = Counter(historical_values)
            baseline_value = (
                sorted(
                    baseline_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[0][0]
                if baseline_counts
                else None
            )

            for value in sorted(current_counts):
                is_anomaly = (
                    enough_history
                    and baseline_value is not None
                    and value not in baseline_counts
                )

                if not enough_history:
                    reason = "insufficient_historical_data"
                elif baseline_value is None:
                    reason = "no_valid_historical_values"
                elif is_anomaly:
                    reason = f"unseen_historical_{field}"
                else:
                    reason = f"observed_in_historical_{field}_baseline"

                findings.append({
                    "client_ip": client_ip,
                    output_field: value,
                    "current_request_count": current_counts[value],
                    "historical_request_count": len(past_events),
                    f"baseline_{output_field}": baseline_value,
                    "is_anomaly": is_anomaly,
                    "reason": reason,
                })

    return findings


def get_historical_window(
    end_time: datetime,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
) -> tuple[datetime, datetime]:
    """Return the historical window ending at end_time."""
    if (
        isinstance(lookback_days, bool)
        or not isinstance(lookback_days, int)
        or lookback_days < 1
    ):
        raise ValueError("lookback_days must be a positive integer")

    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=timezone.utc)

    return end_time - timedelta(days=lookback_days), end_time
