"""Strict reader for sanitized canonical JSONL datasets."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from research.schemas.canonical_event import (
    CanonicalEvent,
    restore_trusted_principal,
)


def read_events(path: Path, *, principal_secret: str | bytes) -> list[CanonicalEvent]:
    """Read canonical events and re-derive trusted principals from their values."""
    events: list[CanonicalEvent] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            data: dict[str, Any] = json.loads(line)
            serialized_principal = data.pop("principal_id")
            if not isinstance(serialized_principal, str):
                raise ValueError("principal_id must be serialized text")
            if not serialized_principal.startswith("principal_"):
                raise ValueError("principal_id is not a trusted pseudonym")
            data["principal_id"] = restore_trusted_principal(serialized_principal)
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
            events.append(CanonicalEvent(**data))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid canonical event at line {line_number}") from exc
    return events
