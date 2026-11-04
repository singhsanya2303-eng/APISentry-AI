"""Safe lexical payload features; raw payload content is never returned."""

import re
from typing import Dict
from urllib.parse import unquote


def payload_lexical_features(payload: str) -> Dict[str, float]:
    """Extract deterministic lexical features from a payload."""
    if not isinstance(payload, str):
        raise ValueError("payload must be a string")
    normalized = payload
    for _ in range(2):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    lowered = normalized.lower()
    length = len(payload)
    return {
        "payload_length": float(len(payload.encode("utf-8"))),
        "digit_ratio": float(sum(character.isdigit() for character in payload) / max(length, 1)),
        "letter_ratio": float(sum(character.isalpha() for character in payload) / max(length, 1)),
        "whitespace_ratio": float(sum(character.isspace() for character in payload) / max(length, 1)),
        "special_ratio": float(
            sum(not character.isalnum() and not character.isspace() for character in payload)
            / max(length, 1)
        ),
        "sql_keyword_count": float(
            sum(len(re.findall(rf"\b{keyword}\b", lowered)) for keyword in (
                "select", "union", "drop", "insert"
            ))
        ),
        "script_marker_count": float(lowered.count("<script")),
        "path_traversal_marker_count": float(
            len(re.findall(r"(?:\.\./|%2e%2e/)", lowered))
        ),
    }
