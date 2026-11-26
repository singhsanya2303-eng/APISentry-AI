"""
Opaque evidence references for MW2.

No raw request ID, identifier, credential, header or payload value is ever
emitted. Callers may hash a raw correlation value with ``opaque_ref``; only the
resulting deterministic UUID5 reference leaves this module.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Iterable

from app.schemas.bot_detection import OPAQUE_REQUEST_ID_PATTERN

ADVANCED_NAMESPACE = uuid.UUID("b6f0c2a4-19d7-5e31-8c4a-7d2f9e0b5a63")
_OPAQUE_RE = re.compile(OPAQUE_REQUEST_ID_PATTERN)
MAX_REFERENCES = 25


def opaque_ref(value: Any, salt: str = "mw2.advanced") -> str:
    """
    Return a stable UUID5 reference for a value without exposing the value.

    The counter guard guarantees the reference is never identical to a supplied
    UUID-shaped value, mirroring the existing bot-detection safeguard.
    """
    raw = value if isinstance(value, str) else repr(value)
    counter = 0
    while True:
        material = f"{salt}:{counter}:{raw}"
        reference = str(uuid.uuid5(ADVANCED_NAMESPACE, material))
        if reference != raw:
            return reference
        counter += 1


def bounded_refs(values: Iterable[Any] | None, limit: int = MAX_REFERENCES) -> list[str]:
    """
    Keep only already-opaque, valid, unique references; drop everything else.

    Raw request IDs are deliberately dropped rather than emitted. Use
    ``opaque_ref`` first if a caller needs correlation from a raw value.
    """
    if not values or limit < 0:
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = getattr(value, "request_id", value)
        if not isinstance(candidate, str):
            continue
        if not _OPAQUE_RE.fullmatch(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        result.append(candidate)
        if len(result) >= limit:
            break
    return result


def dedupe_key(seed: str) -> str:
    """Build a stable, opaque deduplication key from a descriptive seed."""
    return opaque_ref(seed, salt="mw2.dedupe")


__all__ = ["ADVANCED_NAMESPACE", "bounded_refs", "dedupe_key", "opaque_ref"]
