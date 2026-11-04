"""Parse HTTP request records without retaining sensitive material."""

import re
from typing import Dict, Optional
from urllib.parse import parse_qsl, unquote_plus, urlsplit


SAFE_HEADERS = {"accept", "content-type"}
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-access-token",
    "x-auth-token",
    "x-csrf-token",
    "password",
    "user-agent",
}
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
_PATH_ID = re.compile(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,36})(?=/|$)", re.IGNORECASE)


def normalize_endpoint_template(path: str) -> str:
    """Replace numeric and UUID-like path segments with an ID placeholder."""
    normalized = path.split("?", 1)[0].strip()
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    normalized = _PATH_ID.sub("/{id}", normalized)
    return normalized or "/"


def parse_http_request(raw_request: str) -> Dict[str, object]:
    """Parse a raw HTTP request into safe metadata and a body-derived feature set."""
    if not isinstance(raw_request, str) or not raw_request.strip():
        raise ValueError("raw_request must be a non-empty string")

    head, _, body = raw_request.partition("\r\n\r\n")
    if not _:
        head, _, body = raw_request.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("HTTP request is missing a request line")

    request_parts = lines[0].split()
    if len(request_parts) != 3 or not request_parts[0].isalpha():
        raise ValueError("HTTP request has an invalid request line")

    target = urlsplit(request_parts[1])
    query_categories: list[str] = []
    for raw_name, _ in parse_qsl(target.query, keep_blank_values=True):
        name = unquote_plus(raw_name).strip().lower().replace("-", "_")
        category = _SAFE_QUERY_CATEGORIES.get(name)
        if category is not None:
            query_categories.append(category)

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("HTTP request contains an invalid header")
        name, value = line.split(":", 1)
        normalized_name = name.strip().lower()
        if normalized_name in SENSITIVE_HEADERS:
            continue
        if normalized_name in SAFE_HEADERS:
            headers[normalized_name] = value.strip()

    return {
        "method": request_parts[0].upper(),
        "path": target.path or "/",
        "endpoint_template": normalize_endpoint_template(target.path or "/"),
        "http_version": request_parts[2].upper(),
        "safe_headers": headers,
        "query_parameter_count": float(len(query_categories)),
        "safe_query_parameter_categories": query_categories,
        "payload_features": extract_payload_features(body),
    }


def extract_payload_features(payload: Optional[str]) -> Dict[str, float]:
    """Return bounded lexical metadata without returning the payload itself."""
    value = payload or ""
    return {
        "payload_length": float(len(value.encode("utf-8"))),
        "character_count": float(len(value)),
        "digit_count": float(sum(character.isdigit() for character in value)),
        "letter_count": float(sum(character.isalpha() for character in value)),
        "special_character_count": float(
            sum(not character.isalnum() and not character.isspace() for character in value)
        ),
    }
