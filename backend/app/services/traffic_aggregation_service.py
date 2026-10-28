
"""Aggregate API traffic into fixed 10-second windows for anomaly detection."""

from collections import Counter
from datetime import datetime, timezone
from math import isfinite
from typing import Any, Dict, List


WINDOW_SECONDS = 10


def _utc_timestamp(value: datetime) -> datetime:
    """Normalize timestamps to UTC, including naive database timestamps."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def aggregate_traffic_logs(
    logs: List[Any],
    window_seconds: int = WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Aggregate traffic records into aligned time windows.

    Empty windows are omitted. Features are calculated only from the
    supplied records; this function does not query the database.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    buckets: Dict[int, List[Any]] = {}

    for log in logs:
        timestamp = getattr(log, "timestamp", None)
        if not isinstance(timestamp, datetime):
            continue

        timestamp = _utc_timestamp(timestamp)
        bucket_start = int(timestamp.timestamp() // window_seconds) * window_seconds
        buckets.setdefault(bucket_start, []).append(log)

    results: List[Dict[str, Any]] = []

    for bucket_start in sorted(buckets):
        bucket_logs = buckets[bucket_start]

        status_counts = Counter()
        response_times: List[float] = []
        client_ips = set()
        methods = Counter()

        for log in bucket_logs:
            status_code = getattr(log, "status_code", None)
            if (
                isinstance(status_code, int)
                and not isinstance(status_code, bool)
                and 100 <= status_code <= 599
            ):
                status_counts[f"{status_code // 100}xx"] += 1

            response_time = getattr(log, "response_time_ms", None)
            if (
                isinstance(response_time, (int, float))
                and not isinstance(response_time, bool)
                and isfinite(response_time)
                and response_time >= 0
            ):
                response_times.append(float(response_time))

            client_ip = getattr(log, "client_ip", None)
            if isinstance(client_ip, str) and client_ip.strip():
                client_ips.add(client_ip.strip())

            method = getattr(log, "method", None)
            if isinstance(method, str) and method.strip():
                methods[method.strip().upper()] += 1

        results.append(
            {
                "window_start": datetime.fromtimestamp(
                    bucket_start, tz=timezone.utc
                ),
                "window_end": datetime.fromtimestamp(
                    bucket_start + window_seconds, tz=timezone.utc
                ),
                "window_seconds": window_seconds,
                "request_count": len(bucket_logs),
                "unique_client_count": len(client_ips),
                "http_2xx_count": status_counts.get("2xx", 0),
                "http_3xx_count": status_counts.get("3xx", 0),
                "http_4xx_count": status_counts.get("4xx", 0),
                "http_5xx_count": status_counts.get("5xx", 0),
                "mean_response_time_ms": (
                    sum(response_times) / len(response_times)
                    if response_times
                    else 0.0
                ),
                "max_response_time_ms": (
                    max(response_times) if response_times else 0.0
                ),
                "http_method_counts": dict(sorted(methods.items())),
            }
        )

    return results
