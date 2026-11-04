"""Deterministic canonical event persistence."""

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from research.schemas.canonical_event import CanonicalEvent


def write_events(events: list[CanonicalEvent], path: Path) -> str:
    """Atomically write canonical events and return the SHA-256 checksum."""
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("duplicate event_id detected")
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        for event in events:
            payload = event.model_dump(mode="python")
            payload["principal_id"] = str(event.principal_id)
            payload["timestamp"] = event.timestamp.isoformat()
            temporary.write(json.dumps(payload, sort_keys=True) + "\n")
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)
    return sha256_file(path)


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
