"""In-memory privacy boundary for controlled observations."""

from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from research.capture.models import SanitizedCapture
from research.capture.runners import RequestObservation
from research.preprocessing.api_traffic import canonicalize_api_record
from research.preprocessing.http_requests import normalize_endpoint_template
from research.schemas.canonical_event import CanonicalEvent

_SAFE_QUERY_CATEGORIES = {
    "limit": "pagination",
    "offset": "pagination",
    "page": "pagination",
    "per_page": "pagination",
    "sort": "ordering",
    "order": "ordering",
    "filter": "filtering",
    "format": "representation",
    "fields": "representation",
    "include": "representation",
}


def _header_value(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _size(headers: dict[str, str]) -> int:
    value = _header_value(headers, "content-length")
    if value is None:
        return 0
    try:
        return max(0, int(value))
    except ValueError:
        return 0


def _safe_query_categories(url: str) -> list[str]:
    categories: list[str] = []
    for raw_name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        name = unquote_plus(raw_name).strip().lower().replace("-", "_")
        category = _SAFE_QUERY_CATEGORIES.get(name)
        if category is not None:
            categories.append(category)
    return categories


def sanitize_observation(
    observation: RequestObservation,
    *,
    actual_outcome: str,
) -> SanitizedCapture:
    """Drop sensitive material and return only safe metadata."""
    if observation.request_body is not None or observation.response_body is not None:
        raise ValueError("raw bodies must not cross the sanitization boundary")
    timestamp = observation.timestamp
    if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
        raise ValueError("observation timestamp must be timezone-aware")
    parsed = urlsplit(observation.url)
    if not parsed.path.startswith("/"):
        raise ValueError("observation URL must contain an absolute path")
    categories = _safe_query_categories(observation.url)
    return SanitizedCapture(
        event_id=observation.event_id,
        action_id=observation.action.action_id,
        capture_kind=observation.capture_kind,
        timestamp=timestamp.astimezone(timezone.utc),
        method=observation.method,
        url=parsed.path or "/",
        status_code=observation.status_code,
        latency_ms=observation.latency_ms,
        request_size_bytes=_size(observation.request_headers),
        response_size_bytes=_size(observation.response_headers),
        safe_query_parameter_categories=categories,
        query_parameter_count=len(categories),
        expected_outcome=observation.action.expected_outcome,
        actual_outcome=actual_outcome,
        label=observation.action.label.value,
        attack_category=observation.action.attack_category,
        principal_value=observation.action.principal_id,
        session_id=observation.action.session_id,
        campaign_id=observation.action.campaign_id,
    )


def to_canonical_event(
    capture: SanitizedCapture,
    *,
    source_dataset: str,
    principal_secret: str | bytes,
) -> CanonicalEvent:
    """Convert sanitized metadata through the existing canonical boundary."""
    return canonicalize_api_record(
        {
            "event_id": capture.event_id,
            "timestamp": capture.timestamp,
            "session_id": capture.session_id,
            "campaign_id": capture.campaign_id,
            "path": capture.url,
            "method": capture.method,
            "status_code": capture.status_code,
            "latency_ms": capture.latency_ms,
            "request_size_bytes": capture.request_size_bytes,
            "response_size_bytes": capture.response_size_bytes,
            "client_features": {
                "query_parameter_count": float(capture.query_parameter_count),
            },
            "label": capture.label,
            "attack_category": capture.attack_category,
        },
        source_dataset=source_dataset,
        principal_value=capture.principal_value,
        principal_secret=principal_secret,
    )
