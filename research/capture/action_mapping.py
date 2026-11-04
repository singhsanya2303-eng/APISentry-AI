"""Explicit mapping of generated requests to experiment actions."""

from dataclasses import dataclass
from enum import Enum
from typing import Iterable
from urllib.parse import urlsplit

from research.capture.models import (
    CaptureKind,
    ExperimentAction,
    RequestMappingPolicy,
)


class ActionMappingError(ValueError):
    """Raised when a retained request cannot be mapped unambiguously."""


class RequestClassification(str, Enum):
    PRIMARY_API = "primary_api"
    REDIRECT = "redirect"
    PREFLIGHT = "preflight"
    STATIC_ASSET = "static_asset"
    BACKGROUND_POLLING = "background_polling"
    UNRELATED = "unrelated"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class RequestDiagnostic:
    event_id: str
    classification: RequestClassification
    reason: str


@dataclass(frozen=True)
class MappedRequest:
    action: ExperimentAction
    capture_kind: CaptureKind


def classify_request(
    *,
    method: str,
    url: str,
    resource_type: str | None = None,
    is_redirect: bool = False,
    is_preflight: bool = False,
    is_background: bool = False,
    approved_api_prefixes: Iterable[str] = (),
) -> RequestClassification:
    """Classify a request without assigning it an action or label."""
    if is_redirect:
        return RequestClassification.REDIRECT
    if is_preflight or method.upper() == "OPTIONS":
        return RequestClassification.PREFLIGHT
    path = urlsplit(url).path
    prefixes = tuple(approved_api_prefixes)
    if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
        if resource_type in {"document", "stylesheet", "image", "font", "script"}:
            return RequestClassification.STATIC_ASSET
        if is_background or resource_type in {"fetch", "xhr"}:
            return RequestClassification.BACKGROUND_POLLING
        return RequestClassification.UNRELATED
    if is_background:
        return RequestClassification.BACKGROUND_POLLING
    if resource_type in {"document", "stylesheet", "image", "font", "script"}:
        return RequestClassification.STATIC_ASSET
    if resource_type in {"fetch", "xhr"} and not prefixes:
        return RequestClassification.AMBIGUOUS
    return RequestClassification.PRIMARY_API


def _kind(classification: RequestClassification) -> CaptureKind:
    return {
        RequestClassification.PRIMARY_API: CaptureKind.PRIMARY,
        RequestClassification.REDIRECT: CaptureKind.REDIRECT,
        RequestClassification.PREFLIGHT: CaptureKind.PREFLIGHT,
        RequestClassification.STATIC_ASSET: CaptureKind.STATIC_ASSET,
        RequestClassification.BACKGROUND_POLLING: CaptureKind.BACKGROUND,
        RequestClassification.UNRELATED: CaptureKind.UNRELATED,
        RequestClassification.AMBIGUOUS: CaptureKind.AMBIGUOUS,
    }[classification]


def correlate_request(
    *,
    event_id: str,
    classification: RequestClassification,
    action: ExperimentAction | None,
) -> tuple[MappedRequest | None, RequestDiagnostic | None]:
    """Correlate one request to exactly one action or return a diagnostic."""
    if classification in {
        RequestClassification.UNRELATED,
        RequestClassification.STATIC_ASSET,
        RequestClassification.BACKGROUND_POLLING,
    }:
        return None, RequestDiagnostic(
            event_id, classification, "request class is excluded by default"
        )
    if classification is RequestClassification.AMBIGUOUS:
        return None, RequestDiagnostic(
            event_id, classification, "request has no unambiguous action correlation"
        )
    if action is None:
        raise ActionMappingError("retained request has no unambiguous action ID")
    kind = _kind(classification)
    if not action.mapping_policy.retains(kind):
        return None, RequestDiagnostic(
            event_id, classification, "request class is disabled by action policy"
        )
    return MappedRequest(action, kind), None


def map_request_to_action(
    *,
    action: ExperimentAction | None,
    capture_kind: CaptureKind,
) -> MappedRequest | None:
    """Apply the action policy; unrelated or ambiguous requests are rejected."""
    if action is None:
        if capture_kind is CaptureKind.BACKGROUND:
            return None
        raise ActionMappingError("retained request has no unambiguous action ID")
    if not action.capture_policy.retains(capture_kind):
        return None
    if capture_kind is CaptureKind.BACKGROUND and not action.allow_background:
        return None
    return MappedRequest(action=action, capture_kind=capture_kind)
