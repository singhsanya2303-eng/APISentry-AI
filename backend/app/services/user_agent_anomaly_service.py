
"""Detect previously unseen user-agent values per client IP."""

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List


def _get_value(event: Any, field: str) -> Any:
    """Read a field from a dictionary or an event object."""
    if isinstance(event, dict):
        return event.get(field)
    return getattr(event, field, None)


def analyze_user_agent_frequency(
    events: Iterable[Any],
    min_baseline_requests: int = 3,
) -> List[Dict[str, Any]]:
    """Compare each client's user agents against its most frequent baseline.

    A differing user agent is a review signal, not proof of token hijacking.
    Events without a usable client IP or user-agent value are ignored.
    """
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
        user_agent = _get_value(event, "user_agent")

        if not isinstance(client_ip, str) or not client_ip.strip():
            continue

        if not isinstance(user_agent, str) or not user_agent.strip():
            continue

        grouped[client_ip.strip()].append(user_agent.strip())

    results: List[Dict[str, Any]] = []

    for client_ip in sorted(grouped):
        counts = Counter(grouped[client_ip])
        baseline_user_agent, baseline_count = counts.most_common(1)[0]
        enough_baseline = baseline_count >= min_baseline_requests

        for user_agent in sorted(counts):
            is_baseline = user_agent == baseline_user_agent

            if not enough_baseline:
                is_anomaly = False
                reason = "insufficient_baseline_data"
            elif is_baseline:
                is_anomaly = False
                reason = "matches_most_frequent_user_agent"
            else:
                is_anomaly = True
                reason = "user_agent_differs_from_baseline"

            results.append(
                {
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "request_count": counts[user_agent],
                    "baseline_user_agent": baseline_user_agent,
                    "baseline_request_count": baseline_count,
                    "is_baseline_user_agent": is_baseline,
                    "is_anomaly": is_anomaly,
                    "reason": reason,
                }
            )

    return results
