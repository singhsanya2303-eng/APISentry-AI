"""Controlled HTTP and browser execution without raw-object persistence."""

from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid5
from urllib.parse import urljoin

from research.capture.models import CaptureKind, ExperimentAction
from research.capture.target_validation import (
    ApprovedOrigin,
    TargetValidationError,
    validate_redirect,
    validate_request_url,
)


class ResponseInspectionError(RuntimeError):
    """Safe marker for failures after an HTTP response was received."""

    def __init__(self, status_code: int) -> None:
        super().__init__("safe response inspection failed")
        self.status_code = status_code


@dataclass(frozen=True)
class RequestObservation:
    """Minimal in-memory observation passed to the sanitization boundary."""

    action: ExperimentAction
    capture_kind: CaptureKind
    event_id: str
    timestamp: datetime
    method: str
    url: str
    status_code: int
    latency_ms: float
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body: bytes | None
    response_body: bytes | None


def event_id_for_action(action_id: str, sequence: int) -> str:
    """Create a stable request ID within an action execution."""
    if not action_id.strip() or sequence < 0:
        raise ValueError("action ID must be non-blank and sequence non-negative")
    return str(uuid5(NAMESPACE_URL, f"apisentry:{action_id}:{sequence}"))


def _header_int(headers: Any, name: str) -> int:
    value = headers.get(name)
    if value is None:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _header_value(headers: Any, name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    lowered = name.lower()
    for key, candidate in headers.items():
        if str(key).lower() == lowered:
            return candidate
    return None


def execute_http_request(
    *,
    client: Any,
    origin: ApprovedOrigin,
    action: ExperimentAction,
    event_id: str,
    method: str,
    path: str,
    response_inspector: Callable[[bytes], Any] | None = None,
    **request_kwargs: Any,
) -> RequestObservation:
    """Execute one no-redirect HTTP request and validate any redirect target."""
    url = urljoin(f"{origin.scheme}://{origin.hostname}:{origin.port}", path)
    validate_request_url(url, origin)
    start = perf_counter()
    try:
        response = client.request(
            method,
            url,
            follow_redirects=False,
            **request_kwargs,
        )
    except Exception as exc:
        raise RuntimeError("controlled HTTP request failed") from exc
    if response_inspector is not None:
        try:
            response_inspector(response.content)
        except Exception as exc:
            raise ResponseInspectionError(response.status_code) from exc
    latency_ms = (perf_counter() - start) * 1000
    location = _header_value(response.headers, "location")
    if location:
        redirect_url = urljoin(url, location)
        validate_redirect(redirect_url, origin)
    return RequestObservation(
        action=action,
        capture_kind=CaptureKind.PRIMARY,
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        status_code=response.status_code,
        latency_ms=latency_ms,
        request_headers=dict(response.request.headers),
        response_headers=dict(response.headers),
        request_body=None,
        response_body=None,
    )


def attach_playwright_origin_guard(page: Any, origin: ApprovedOrigin) -> None:
    """Validate every browser request and fail closed for off-origin traffic."""

    def check_request(request: Any) -> None:
        try:
            validate_request_url(request.url, origin)
        except TargetValidationError as exc:
            raise RuntimeError("browser request escaped the approved local origin") from exc

    page.on("request", check_request)


def execute_playwright_navigation(
    *,
    page: Any,
    origin: ApprovedOrigin,
    action: ExperimentAction,
    event_id: str,
    path: str,
) -> RequestObservation:
    """Navigate once, retain only the primary response metadata, and disable redirects."""
    attach_playwright_origin_guard(page, origin)
    url = urljoin(f"{origin.scheme}://{origin.hostname}:{origin.port}", path)
    validate_request_url(url, origin)
    start = perf_counter()
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=30_000)
    except Exception as exc:
        raise RuntimeError("controlled browser navigation failed") from exc
    if response is None:
        raise RuntimeError("controlled browser navigation returned no response")
    location = response.header_value("location")
    if location:
        validate_redirect(urljoin(url, location), origin)
    return RequestObservation(
        action=action,
        capture_kind=CaptureKind.PRIMARY,
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        method="GET",
        url=url,
        status_code=response.status,
        latency_ms=(perf_counter() - start) * 1000,
        request_headers=dict(response.request.all_headers()),
        response_headers=dict(response.all_headers()),
        request_body=None,
        response_body=None,
    )
