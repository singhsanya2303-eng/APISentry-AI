"""Convert source-neutral API records into canonical events."""

import hashlib
import hmac
import math
import re
import secrets
from typing import Any, Mapping

from research.schemas.canonical_event import (
    CanonicalEvent,
    TrustedPrincipalId,
    _TRUST_MARKER,
)
from research.preprocessing.http_requests import normalize_endpoint_template

_SENSITIVE_NAME = re.compile(
    r"(authorization|cookie|password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_MIN_SECRET_BYTES = 32
_REJECTED_KEY_VALUES = {b"development", b"secret", b"password", b"test"}


def generate_principal_secret() -> bytes:
    """Generate a 256-bit key suitable for principal pseudonymization."""
    return secrets.token_bytes(_MIN_SECRET_BYTES)


def anonymize_principal(value: str, *, secret: str | bytes) -> TrustedPrincipalId:
    """Return a stable HMAC pseudonym; this is not irreversible anonymization."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("principal value must be a non-empty string")
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if (
        not isinstance(key, bytes)
        or len(key) < _MIN_SECRET_BYTES
        or key in _REJECTED_KEY_VALUES
        or len(set(key)) == 1
    ):
        raise ValueError("principal pseudonymization secret must be at least 32 bytes")
    digest = hmac.new(
        key,
        value.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return TrustedPrincipalId(f"principal_{digest}", marker=_TRUST_MARKER)


def _safe_numeric_features(values: Mapping[str, Any] | None) -> dict[str, float]:
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise ValueError("numeric features must be a mapping")

    result: dict[str, float] = {}
    for name, value in values.items():
        if _SENSITIVE_NAME.search(str(name)):
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            numeric_value = float(value)
            if not math.isfinite(numeric_value):
                raise ValueError("numeric features must contain finite values")
            result[str(name)] = numeric_value
    return result


def canonicalize_api_record(
    record: Mapping[str, Any],
    *,
    source_dataset: str,
    principal_value: str,
    principal_secret: str | bytes,
) -> CanonicalEvent:
    """Normalize a source record while excluding sensitive fields."""
    method = record.get("method")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("record requires a non-blank method")
    endpoint = record.get("endpoint_template") or record.get("path")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("record requires a non-blank path or endpoint_template")

    return CanonicalEvent(
        event_id=record.get("event_id"),
        timestamp=record.get("timestamp"),
        principal_id=anonymize_principal(
            principal_value,
            secret=principal_secret,
        ),
        session_id=record.get("session_id"),
        campaign_id=record.get("campaign_id"),
        method=method.strip().upper(),
        endpoint_template=normalize_endpoint_template(endpoint),
        status_code=record.get("status_code"),
        latency_ms=record.get("latency_ms", record.get("latency", 0)),
        request_size_bytes=record.get("request_size_bytes", 0),
        response_size_bytes=record.get("response_size_bytes", 0),
        client_features=_safe_numeric_features(record.get("client_features")),
        network_features=_safe_numeric_features(record.get("network_features")),
        label=record.get("label"),
        attack_category=record.get("attack_category"),
        source_dataset=source_dataset,
    )
