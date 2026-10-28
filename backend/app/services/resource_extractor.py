import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from app.schemas.bola import ResourceIdentifier, ResourceAccessEvent
from app.models.traffic import APITrafficLog

# Known static non-resource keywords that should not be classified as object identifiers or resource parameters
STATIC_NON_RESOURCE_KEYWORDS = {
    "api", "v1", "v2", "v3", "v4", "health", "status", "profile", "me", "self",
    "login", "logout", "auth", "register", "docs", "openapi.json", "redoc",
    "search", "export", "import", "download", "upload", "ping", "dashboard",
    "metrics", "config", "settings", "info", "overview", "list", "all",
    "summary", "details", "active", "pending", "history"
}

# Regex definitions
UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUMERIC_REGEX = re.compile(r"^\d+$")
ALPHANUMERIC_ID_REGEX = re.compile(r"^(?:[a-zA-Z]{2,10}_[a-zA-Z0-9]+|[a-zA-Z0-9]*\d[a-zA-Z0-9]*[a-zA-Z][a-zA-Z0-9]*|[a-zA-Z][a-zA-Z0-9]*\d[a-zA-Z0-9]*)$")

SAFE_ACTOR_HEADERS = {"x-user-id", "x-actor-id", "x-user-sub", "x-client-id"}
SAFE_ACTOR_QUERY_PARAMS = {"user_id", "actor_id", "sub"}


def is_valid_uuid(val: str) -> bool:
    """Check if string matches standard UUID format."""
    return bool(UUID_REGEX.match(val))


def is_numeric_id(val: str) -> bool:
    """Check if string is a pure numeric ID."""
    return bool(NUMERIC_REGEX.match(val))


def is_candidate_alphanumeric_id(val: str) -> bool:
    """Check if string matches prefixed or mixed alphanumeric ID pattern."""
    if val.lower() in STATIC_NON_RESOURCE_KEYWORDS:
        return False
    return bool(ALPHANUMERIC_ID_REGEX.match(val))


def singularize_resource_name(name: str) -> str:
    """Convert plural collection name to singular parameter name for normalized path templates."""
    lower = name.lower()
    if lower.endswith("ies") and len(lower) > 3:
        return lower[:-3] + "y"
    elif lower.endswith("s") and not lower.endswith("ss") and len(lower) > 1:
        return lower[:-1]
    return lower


def extract_candidate_resources(path: str) -> Tuple[List[ResourceIdentifier], str]:
    """
    Parse a URI path, identify candidate resource references, and construct a normalized endpoint template.

    Returns:
    - extracted_resources: List[ResourceIdentifier]
    - normalized_endpoint: str
    """
    segments = [seg for seg in path.strip().split("/") if seg]
    if not segments:
        return [], "/"

    extracted_resources: List[ResourceIdentifier] = []
    normalized_segments: List[str] = []

    for i, seg in enumerate(segments):
        prev_seg = segments[i - 1] if i > 0 else ""
        is_uuid = is_valid_uuid(seg)
        is_num = is_numeric_id(seg)
        is_alphanumeric = is_candidate_alphanumeric_id(seg)

        is_candidate_id = is_uuid or is_num or (is_alphanumeric and prev_seg.lower() not in STATIC_NON_RESOURCE_KEYWORDS)

        if is_candidate_id and seg.lower() not in STATIC_NON_RESOURCE_KEYWORDS:
            # Determine collection / resource type name
            if prev_seg and prev_seg.lower() not in STATIC_NON_RESOURCE_KEYWORDS and not is_numeric_id(prev_seg) and not is_valid_uuid(prev_seg):
                resource_type = prev_seg.lower()
                confidence = 0.95 if is_uuid else (0.90 if is_num else 0.85)
            else:
                resource_type = "resource"
                confidence = 0.40 if is_num else 0.30  # Ambiguous path context

            res_id = ResourceIdentifier(
                resource_type=resource_type,
                resource_id=seg,
                position=i,
                is_numeric=is_num,
                is_uuid=is_uuid,
                confidence=confidence
            )
            extracted_resources.append(res_id)

            placeholder = f"{{{singularize_resource_name(resource_type)}_id}}" if resource_type != "resource" else "{id}"
            normalized_segments.append(placeholder)
        else:
            normalized_segments.append(seg)

    normalized_endpoint = "/" + "/".join(normalized_segments)
    return extracted_resources, normalized_endpoint


def extract_safe_actor_id(
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """
    Safely extract non-sensitive actor identity.
    Strictly avoids Authorization headers, Bearer tokens, API keys, cookies, passwords, and secrets.
    """
    if headers:
        norm_headers = {k.lower(): str(v) for k, v in headers.items()}
        for safe_key in SAFE_ACTOR_HEADERS:
            if safe_key in norm_headers and norm_headers[safe_key]:
                return norm_headers[safe_key].strip()

    if query_params:
        norm_params = {k.lower(): str(v) for k, v in query_params.items()}
        for safe_key in SAFE_ACTOR_QUERY_PARAMS:
            if safe_key in norm_params and norm_params[safe_key]:
                val = norm_params[safe_key].strip()
                if val and val != "***MASKED***":
                    return val

    return None


def extract_resource_access_event(
    request_id: str,
    timestamp: datetime,
    method: str,
    path: str,
    client_ip: str,
    status_code: int,
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, Any]] = None
) -> ResourceAccessEvent:
    """
    Construct a ResourceAccessEvent from request metadata.
    Identifies candidate resource references and normalizes endpoint path safely.
    """
    extracted_resources, normalized_endpoint = extract_candidate_resources(path)
    actor_id = extract_safe_actor_id(headers=headers, query_params=query_params)

    primary_resource = extracted_resources[-1] if extracted_resources else None
    parent_resource = extracted_resources[-2] if len(extracted_resources) > 1 else None
    has_object_ref = len(extracted_resources) > 0

    return ResourceAccessEvent(
        request_id=request_id,
        timestamp=timestamp,
        method=method.upper(),
        raw_path=path,
        client_ip=client_ip,
        status_code=status_code,
        normalized_endpoint=normalized_endpoint,
        actor_id=actor_id,
        primary_resource=primary_resource,
        parent_resource=parent_resource,
        extracted_resources=extracted_resources,
        has_object_reference=has_object_ref
    )


def extract_from_traffic_log(
    log: APITrafficLog,
    headers: Optional[Dict[str, str]] = None
) -> ResourceAccessEvent:
    """Convenience helper to extract ResourceAccessEvent from an existing APITrafficLog ORM object."""
    return extract_resource_access_event(
        request_id=log.request_id,
        timestamp=log.timestamp,
        method=log.method,
        path=log.path,
        client_ip=log.client_ip,
        status_code=log.status_code,
        headers=headers,
        query_params=log.query_params
    )
