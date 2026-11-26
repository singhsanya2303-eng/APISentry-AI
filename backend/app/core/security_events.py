"""Structured security-event logging with strict sensitive-data redaction.

Security events are operational/audit signals. They must never include raw
passwords, tokens, API keys, secrets, cookies, or sensitive payload bodies.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

_SECURITY_LOGGER = logging.getLogger("apisentry.security.events")

_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "authorization",
    "api_key",
    "apikey",
    "x-api-key",
    "secret",
    "client_secret",
    "jwt_secret_key",
    "cookie",
    "set-cookie",
    "session",
    "csrf",
    "credential",
    "credentials",
    "private_key",
    "database_url",
}
_REDACTED = "***REDACTED***"


def _looks_sensitive_key(key: str) -> bool:
    k = str(key).strip().lower().replace("-", "_")
    if k in _SENSITIVE_KEYS:
        return True
    return any(
        marker in k
        for marker in (
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "cookie",
            "credential",
        )
    )


def redact_sensitive(value: Any, *, _depth: int = 0) -> Any:
    """Redact sensitive fields recursively. Bounded depth prevents abuse."""
    if _depth > 6:
        return _REDACTED
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if _looks_sensitive_key(str(k)):
                out[str(k)] = _REDACTED
            else:
                out[str(k)] = redact_sensitive(v, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        redacted = [redact_sensitive(v, _depth=_depth + 1) for v in value[:50]]
        if len(value) > 50:
            redacted.append("...<truncated>")
        return redacted
    if isinstance(value, (str, bytes)):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        # Avoid logging large blobs/bodies.
        if len(text) > 512:
            return text[:512] + "...<truncated>"
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def log_security_event(event: str, *, severity: str = "warning", **fields: Any) -> None:
    """Emit a structured security event with redacted fields."""
    payload = {
        "event": str(event),
        "severity": str(severity).lower(),
        **redact_sensitive(fields),
    }
    level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }.get(payload["severity"], logging.WARNING)
    _SECURITY_LOGGER.log(level, "security_event %s", payload, extra={"security_event": payload})