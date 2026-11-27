"""In-process auth rate limiting helpers.

Baseline abuse protection for sensitive auth endpoints. Per-process only;
distributed deployments should use a shared store. Design prioritizes
concurrency safety, bounded memory, stale-entry cleanup, and forwarded-IP
spoofing resistance (only TRUSTED_PROXIES can influence X-Forwarded-For).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.core.security_events import log_security_event
from app.utils.middleware import extract_client_ip


_LOCK = threading.Lock()
_BUCKETS: Dict[Tuple[str, str], Deque[float]] = {}
_MAX_BUCKETS = 10_000
_LAST_CLEANUP_MONOTONIC = 0.0
_CLEANUP_INTERVAL_SECONDS = 60.0


def _client_ip(request: Request) -> str:
    # Use trusted-proxy-aware extraction to resist XFF spoofing from untrusted peers.
    trusted = getattr(settings, "TRUSTED_PROXIES", []) or []
    ip = extract_client_ip(request, trusted)
    return (ip or "unknown").strip() or "unknown"


def reset_auth_rate_limits() -> None:
    global _LAST_CLEANUP_MONOTONIC
    with _LOCK:
        _BUCKETS.clear()
        _LAST_CLEANUP_MONOTONIC = 0.0


def _cleanup_expired(now: float, window: int) -> None:
    cutoff = now - window
    stale_keys = []
    for key, bucket in _BUCKETS.items():
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if not bucket:
            stale_keys.append(key)
    for key in stale_keys:
        _BUCKETS.pop(key, None)


def _maybe_cleanup(now: float, window: int) -> None:
    global _LAST_CLEANUP_MONOTONIC
    if len(_BUCKETS) < _MAX_BUCKETS and (now - _LAST_CLEANUP_MONOTONIC) < _CLEANUP_INTERVAL_SECONDS:
        return
    _cleanup_expired(now, window)
    _LAST_CLEANUP_MONOTONIC = now
    # Hard bound: if still too large, evict oldest buckets deterministically.
    if len(_BUCKETS) > _MAX_BUCKETS:
        overflow = len(_BUCKETS) - _MAX_BUCKETS
        oldest = sorted(
            _BUCKETS.items(),
            key=lambda kv: kv[1][0] if kv[1] else 0.0,
        )[:overflow]
        for key, _ in oldest:
            _BUCKETS.pop(key, None)


def enforce_auth_rate_limit(request: Request, scope: str) -> None:
    """Enforce a sliding-window limit for auth endpoints.

    Disabled when AUTH_RATE_LIMIT_ENABLED is false. Limits are per-process.
    Uses trusted-proxy-aware client IP extraction to resist forwarded-header spoofing.
    """
    if not getattr(settings, "AUTH_RATE_LIMIT_ENABLED", True):
        return

    try:
        limit = int(getattr(settings, "AUTH_RATE_LIMIT_REQUESTS", 20))
        window = int(getattr(settings, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 60))
    except Exception:
        limit, window = 20, 60
    if limit <= 0 or window <= 0:
        return

    now = time.monotonic()
    key = (_client_ip(request), str(scope or "auth"))
    with _LOCK:
        _maybe_cleanup(now, window)
        bucket = _BUCKETS.get(key)
        if bucket is None:
            bucket = deque()
            _BUCKETS[key] = bucket
        cutoff = now - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int(window - (now - bucket[0])) if bucket else window)
            log_security_event(
                "auth.rate_limited",
                severity="warning",
                scope=scope,
                client_ip=key[0],
                path=str(request.url.path),
                method=request.method,
                retry_after=retry_after,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please retry later.",
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)