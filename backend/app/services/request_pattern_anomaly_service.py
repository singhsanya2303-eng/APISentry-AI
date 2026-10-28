"""Batch-level HTTP method and request-path frequency review signals.

These detectors compare each client's observed values within the supplied batch.
They are review signals, not proof of an attack, and do not maintain historical baselines.
"""
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List


def _get_value(event: Any, field: str) -> Any:
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def _analyze_frequency(
    events: Iterable[Any],
    field: str,
    output_field: str,
    min_baseline_requests: int,
) -> List[Dict[str, Any]]:
    if (
        isinstance(min_baseline_requests, bool)
        or not isinstance(min_baseline_requests, int)
        or min_baseline_requests < 1
    ):
        raise ValueError("min_baseline_requests must be a positive integer")

    grouped: Dict[str, List[str]] = defaultdict(list)
    for event in events:
        if event is None:
            continue
        client_ip = _get_value(event, "client_ip")
        value = _get_value(event, field)
        if not isinstance(client_ip, str) or not client_ip.strip():
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        grouped[client_ip.strip()].append(value.strip())

    results: List[Dict[str, Any]] = []
    for client_ip in sorted(grouped):
        counts = Counter(grouped[client_ip])
        baseline_value, baseline_count = sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )[0]
        enough_baseline = baseline_count >= min_baseline_requests

        for value in sorted(counts):
            is_baseline = value == baseline_value
            if not enough_baseline:
                is_anomaly = False
                reason = "insufficient_baseline_data"
            elif is_baseline:
                is_anomaly = False
                reason = f"matches_most_frequent_{field}"
            else:
                is_anomaly = True
                reason = f"{field}_differs_from_baseline"

            results.append({
                "client_ip": client_ip,
                output_field: value,
                "request_count": counts[value],
                f"baseline_{output_field}": baseline_value,
                "baseline_request_count": baseline_count,
                f"is_baseline_{output_field}": is_baseline,
                "is_anomaly": is_anomaly,
                "reason": reason,
            })
    return results


def analyze_http_method_frequency(
    events: Iterable[Any],
    min_baseline_requests: int = 3,
) -> List[Dict[str, Any]]:
    """Flag methods differing from a client's most frequent method in this batch."""
    return _analyze_frequency(
        events, "method", "http_method", min_baseline_requests
    )


def analyze_request_path_frequency(
    events: Iterable[Any],
    min_baseline_requests: int = 3,
) -> List[Dict[str, Any]]:
    """Flag paths differing from a client's most frequent exact path in this batch."""
    return _analyze_frequency(
        events, "path", "request_path", min_baseline_requests
    )
