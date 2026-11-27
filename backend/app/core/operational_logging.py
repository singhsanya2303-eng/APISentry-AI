"""Structured operational logging helpers.

These helpers emit single-line JSON records through standard logging. They are
used for startup/shutdown, readiness and unhandled-error reporting. All fields
pass through the existing redaction contract before serialization, so secrets
and request bodies are never written to operational logs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.core.security_events import redact_sensitive


def format_log_event(event: str, **fields: Any) -> str:
    """Serialize a redacted operational event as stable JSON."""
    payload = {
        "event": str(event),
        **redact_sensitive(fields),
    }
    return json.dumps(payload, sort_keys=True, default=str)


def log_operation(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a redacted structured event without raising into the request path."""
    try:
        logger.info("%s", format_log_event(event, **fields))
    except Exception:  # pragma: no cover - logging must never break the app
        logger.debug("structured log emission failed for event=%s", event)
