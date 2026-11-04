"""Strict local-origin and redirect validation for controlled collection."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class TargetValidationError(ValueError):
    """Raised when a target or redirect is outside the approved local origin."""


@dataclass(frozen=True)
class ApprovedOrigin:
    scheme: str
    hostname: str
    port: int
    resolved_addresses: frozenset[str]


def _resolve(hostname: str) -> frozenset[str]:
    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise TargetValidationError(f"unable to resolve target hostname: {hostname}") from exc
    if not addresses:
        raise TargetValidationError("target hostname resolved to no addresses")
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_loopback:
                raise TargetValidationError(
                    f"target hostname resolved to non-loopback address: {address}"
                )
        except ValueError as exc:
            raise TargetValidationError("target resolved to an invalid IP address") from exc
    return frozenset(addresses)


def validate_target_origin(url: str) -> ApprovedOrigin:
    """Validate and resolve an explicitly configured loopback origin."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise TargetValidationError("target must use HTTP(S) without embedded credentials")
    if not parsed.hostname or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise TargetValidationError("target must be an origin without path, query, or fragment")
    try:
        addresses = _resolve(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError("target has an invalid port") from exc
    if not 1 <= port <= 65535:
        raise TargetValidationError("target port is outside the valid range")
    if not any(ipaddress.ip_address(address).is_loopback for address in addresses):
        raise TargetValidationError("target must resolve to loopback")
    return ApprovedOrigin(parsed.scheme, parsed.hostname.lower(), port, addresses)


def validate_request_url(url: str, origin: ApprovedOrigin) -> None:
    """Reject requests and redirects outside the exact approved origin."""
    parsed = urlsplit(url)
    if parsed.scheme != origin.scheme or parsed.hostname is None:
        raise TargetValidationError("request URL is outside the approved scheme")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError("request URL has an invalid port") from exc
    if parsed.hostname.lower() != origin.hostname or port != origin.port:
        raise TargetValidationError("request URL is outside the approved origin")
    addresses = _resolve(parsed.hostname)
    if addresses != origin.resolved_addresses:
        raise TargetValidationError("hostname resolution changed; possible DNS rebinding")


def validate_redirect(url: str, origin: ApprovedOrigin) -> None:
    """Validate each redirect destination independently."""
    validate_request_url(url, origin)
