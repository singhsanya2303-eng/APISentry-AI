
"""Detect unusual request-path frequencies per client IP."""

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List


def _get_value(event: Any, field: str) -> Any:
    """Read a field from a dictionary or an event object."""
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def analyze_request_path_frequency(
    events: Iterable[Any],
    min_baseline_requests: int = 10,
    max_path_frequency: float = 0.05,
) -> List[Dict[str, Any]]:
    """Flag rare normalized endpoints in the supplied client traffic batch.

    The baseline is calculated from the supplied events. For meaningful
    detection, callers should provide historical baseline events separately
    from the events they want to score.

    An unusual endpoint is a review signal, not proof of an attack.
    """
    if (
        isinstance(min_baseline_requests, bool)
        or not isinstance(min_baseline_requests, int)
        or min_baseline_requests < 1
    ):
        raise ValueError("min_baseline_requests must be a positive integer")

    if (
        isinstance(max_path_frequency, bool)
        or not isinstance(max_path_frequency, (int, float))
        or isinstance(max_path_frequency, bool)
        or not 0.0 <= max_path_frequency <= 1.0
    ):
        raise ValueError("max_path_frequency must be between 0 and 1")

    grouped: Dict[str, List[str]] = defaultdict(list)

    for event in events:
        if event is None:
            continue

        client_ip = _get_value(event, "client_ip")
        endpoint = _get_value(event, "normalized_endpoint")

        if not isinstance(client_ip, str) or not client_ip.strip():
            continue
        if not isinstance(endpoint, str) or not endpoint.strip():
            continue

        grouped[client_ip.strip()].append(endpoint.strip())

    results: List[Dict[str, Any]] = []

    for client_ip in sorted(grouped):
        endpoint_counts = Counter(grouped[client_ip])
        total_requests = sum(endpoint_counts.values())
        enough_baseline = total_requests >= min_baseline_requests

        for endpoint in sorted(endpoint_counts):
            count = endpoint_counts[endpoint]
            frequency = count / total_requests
            is_anomaly = (
                enough_baseline
                and frequency <= max_path_frequency
            )

            if not enough_baseline:
                reason = "insufficient_baseline_data"
            elif is_anomaly:
                reason = "rare_normalized_endpoint"
            else:
                reason = "endpoint_frequency_within_configured_range"

            results.append(
                {
                    "client_ip": client_ip,
                    "normalized_endpoint": endpoint,
                    "request_count": count,
                    "total_requests": total_requests,
                    "path_frequency": frequency,
                    "is_anomaly": is_anomaly,
                    "reason": reason,
                }
            )

    return results
