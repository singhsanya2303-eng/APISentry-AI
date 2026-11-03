
"""Detect unusual HTTP-method frequencies per client IP."""

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List


def _get_value(event: Any, field: str) -> Any:
    """Read a field from a dictionary or an event object."""
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def analyze_http_method_frequency(
    events: Iterable[Any],
    min_baseline_requests: int = 10,
    min_method_count: int = 1,
    max_method_frequency: float = 0.05,
) -> List[Dict[str, Any]]:
    """Flag methods that are rare in a client's supplied baseline batch.

    This is a frequency-based review signal, not proof of an attack.
    The baseline is calculated from the supplied batch; callers should
    provide historical baseline events separately from events being scored.
    """
    if (
        isinstance(min_baseline_requests, bool)
        or not isinstance(min_baseline_requests, int)
        or min_baseline_requests < 1
    ):
        raise ValueError("min_baseline_requests must be a positive integer")

    if (
        isinstance(min_method_count, bool)
        or not isinstance(min_method_count, int)
        or min_method_count < 1
    ):
        raise ValueError("min_method_count must be a positive integer")

    if (
        isinstance(max_method_frequency, bool)
        or not isinstance(max_method_frequency, (int, float))
        or not 0.0 <= max_method_frequency <= 1.0
    ):
        raise ValueError("max_method_frequency must be between 0 and 1")

    grouped: Dict[str, List[str]] = defaultdict(list)

    for event in events:
        if event is None:
            continue

        client_ip = _get_value(event, "client_ip")
        method = _get_value(event, "method")

        if not isinstance(client_ip, str) or not client_ip.strip():
            continue
        if not isinstance(method, str) or not method.strip():
            continue

        grouped[client_ip.strip()].append(method.strip().upper())

    results: List[Dict[str, Any]] = []

    for client_ip in sorted(grouped):
        method_counts = Counter(grouped[client_ip])
        total_requests = sum(method_counts.values())
        enough_baseline = total_requests >= min_baseline_requests

        for method in sorted(method_counts):
            count = method_counts[method]
            frequency = count / total_requests

            is_anomaly = (
                enough_baseline
                and count >= min_method_count
                and frequency <= max_method_frequency
            )

            if not enough_baseline:
                reason = "insufficient_baseline_data"
            elif is_anomaly:
                reason = "rare_http_method"
            else:
                reason = "method_frequency_within_configured_range"

            results.append(
                {
                    "client_ip": client_ip,
                    "http_method": method,
                    "request_count": count,
                    "total_requests": total_requests,
                    "method_frequency": frequency,
                    "is_anomaly": is_anomaly,
                    "reason": reason,
                }
            )

    return results
