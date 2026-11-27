import ipaddress
import time
import uuid
import logging
from datetime import datetime, timezone
from functools import partial
from typing import Dict, Any, List, Optional
import anyio
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from app.core.config import settings
from app.core.security_events import log_security_event
from app.services.traffic_service import save_traffic_log

logger = logging.getLogger("apisentry.middleware")

# Sensitive parameter keys to mask (case-insensitive)
SENSITIVE_PARAM_KEYS = {
    "password", "pass", "pwd", "token", "access_token", "refresh_token",
    "secret", "api_key", "apikey", "key", "auth", "authorization",
    "credential", "private", "ssn", "credit_card"
}


def sanitize_query_params(query_params: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize query parameters by masking sensitive values."""
    sanitized = {}
    for key, value in query_params.items():
        if key.lower() in SENSITIVE_PARAM_KEYS:
            sanitized[key] = "***MASKED***"
        else:
            sanitized[key] = value
    return sanitized


def is_trusted_proxy(peer_ip: str, trusted_proxies: List[str]) -> bool:
    """Check if peer_ip matches any configured trusted proxy IP or CIDR network."""
    if not peer_ip or not trusted_proxies:
        return False
    try:
        peer_addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    for proxy in trusted_proxies:
        proxy_str = str(proxy).strip()
        if not proxy_str:
            continue
        try:
            if "/" in proxy_str:
                if peer_addr in ipaddress.ip_network(proxy_str, strict=False):
                    return True
            else:
                if peer_addr == ipaddress.ip_address(proxy_str):
                    return True
        except ValueError:
            continue
    return False


def extract_client_ip(request: Request, trusted_proxies: Optional[List[str]] = None) -> str:
    """
    Safely extract client IP address.

    1. Determine the direct peer IP from request.client.host.
    2. If direct peer is not trusted or trusted_proxies is empty, return direct peer IP.
    3. If direct peer is trusted, defensively parse X-Forwarded-For.
    """
    direct_peer = request.client.host if (request.client and request.client.host) else "unknown"

    if trusted_proxies is None:
        trusted_proxies = getattr(settings, "TRUSTED_PROXIES", [])

    if not is_trusted_proxy(direct_peer, trusted_proxies):
        return direct_peer

    forwarded_header = request.headers.get("x-forwarded-for")
    if not forwarded_header:
        return direct_peer

    # Parse comma-separated IPs (format: client, proxy1, proxy2)
    raw_hops = [hop.strip() for hop in forwarded_header.split(",") if hop.strip()]
    if not raw_hops:
        return direct_peer

    # Validate candidate IP defensively
    candidate_ip = raw_hops[0]
    try:
        valid_addr = ipaddress.ip_address(candidate_ip)
        return str(valid_addr)
    except ValueError:
        return direct_peer


def extract_verified_actor_identity(request: Request) -> Optional[str]:
    """
    Extract actor identity strictly from a verified server-side authentication context.

    Security Contract:
    - Never trust unverified client-supplied headers (e.g., X-User-ID, X-Actor-ID).
    - Never trust arbitrary client query parameters (e.g., ?user_id=..., ?actor_id=...).
    - Extract exclusively from verified server-side request state populated by trusted
      authentication dependencies or middleware (e.g., request.state.actor_id,
      request.state.user_id, or authenticated user objects on request.state).
    - If no trusted authentication context is present, returns None as a safe fallback.
    """
    if not hasattr(request, "state"):
        return None

    state = request.state

    # 1. Check explicit verified actor/user identifiers set by auth handlers
    for attr in ("actor_id", "user_id", "authenticated_actor_id", "authenticated_user_id"):
        val = getattr(state, attr, None)
        if val is not None and str(val).strip():
            return str(val).strip()

    # 2. Check verified user object if present
    user = getattr(state, "user", None)
    if user is not None:
        if hasattr(user, "is_authenticated") and not user.is_authenticated:
            return None
        if hasattr(user, "identity") and user.identity:
            return str(user.identity).strip()
        if hasattr(user, "id") and user.id is not None:
            return str(user.id).strip()
        if isinstance(user, dict):
            for key in ("actor_id", "user_id", "id", "sub"):
                if key in user and user[key]:
                    return str(user[key]).strip()

    return None


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to capture and log API request metadata safely without storing
    request bodies or sensitive credentials. Integrates with the persistence layer.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()

        # 1. Resolve or generate unique Request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        # 2. Extract metadata safely
        client_ip = extract_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        method = request.method
        path = request.url.path
        raw_query_params = dict(request.query_params)
        sanitized_query_params = sanitize_query_params(raw_query_params)
        utc_timestamp = datetime.now(timezone.utc)

        response: Response = None
        try:
            response = await call_next(request)
        except Exception as exc:
            # Measure processing duration in case of unhandled exception
            process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            actor_id = extract_verified_actor_identity(request)
            self._log_safely({
                "request_id": request_id,
                "timestamp": utc_timestamp.isoformat(),
                "method": method,
                "path": path,
                "query_params": sanitized_query_params,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "status_code": 500,
                "duration_ms": process_time_ms,
                "error_type": type(exc).__name__,
                "actor_id": actor_id
            })
            # Attempt to persist 500 server error log safely
            await anyio.to_thread.run_sync(
                partial(
                    self._persist_safely,
                    request_id=request_id,
                    method=method,
                    path=path,
                    query_params=sanitized_query_params,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=500,
                    response_time_ms=process_time_ms,
                    timestamp=utc_timestamp,
                    actor_id=actor_id
                )
            )
            raise exc

        # 3. Calculate latency and attach headers
        process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time_ms}ms"

        # 4. Resolve verified actor identity (after route handlers / auth dependencies have run)
        actor_id = extract_verified_actor_identity(request)

        # 5. Log structured metadata safely
        self._log_safely({
            "request_id": request_id,
            "timestamp": utc_timestamp.isoformat(),
            "method": method,
            "path": path,
            "query_params": sanitized_query_params,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "status_code": response.status_code,
            "duration_ms": process_time_ms,
            "actor_id": actor_id
        })

        # 6. Persist to database safely without breaking response flow
        await anyio.to_thread.run_sync(
            partial(
                self._persist_safely,
                request_id=request_id,
                method=method,
                path=path,
                query_params=sanitized_query_params,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=response.status_code,
                response_time_ms=process_time_ms,
                timestamp=utc_timestamp,
                actor_id=actor_id
            )
        )

        return response

    def _log_safely(self, log_data: Dict[str, Any]) -> None:
        """Safely emit log entry without crashing middleware flow."""
        try:
            logger.info("API Request Log: %s", log_data)
        except Exception as log_exc:
            print(f"[Fallback Log Error] {log_exc}")

    def _persist_safely(
        self,
        request_id: str,
        method: str,
        path: str,
        query_params: Dict[str, Any],
        client_ip: str,
        user_agent: str,
        status_code: int,
        response_time_ms: float,
        timestamp: datetime,
        actor_id: Optional[str] = None
    ) -> None:
        """Safely invoke persistence layer without propagating exceptions to client."""
        try:
            save_traffic_log(
                request_id=request_id,
                method=method,
                path=path,
                query_params=query_params,
                client_ip=client_ip,
                user_agent=user_agent,
                status_code=status_code,
                response_time_ms=response_time_ms,
                timestamp=timestamp,
                actor_id=actor_id
            )
        except Exception as p_exc:
            logger.error("Persistence invocation failed for request %s: %s", request_id, p_exc)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach conservative security headers without leaking sensitive info."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if not getattr(settings, "SECURITY_HEADERS_ENABLED", True):
            return response
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        # Keep CSP compatible with FastAPI docs; tighten API/default policy.
        is_docs = (
            request.url.path.startswith("/docs")
            or request.url.path.startswith("/redoc")
            or request.url.path.startswith(f"{settings.API_V1_STR}/openapi.json")
        )
        if is_docs:
            csp = (
                "default-src 'self'; img-src 'self' data: https:; "
                "style-src 'self' 'unsafe-inline' https:; "
                "script-src 'self' 'unsafe-inline' https:; "
                "connect-src 'self' https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
            )
        else:
            connect_src = "'self' https:" if str(getattr(settings, "ENVIRONMENT", "")).strip().lower() == "production" else "'self' http: https:"
            csp = (
                "default-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                f"connect-src {connect_src}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
            )
        response.headers.setdefault("Content-Security-Policy", csp)
        if str(getattr(settings, "ENVIRONMENT", "")).strip().lower() == "production":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RequestSizeLimitMiddleware:
    """ASGI middleware enforcing request body size limits.

    Checks Content-Length for early reject and always counts actual streamed bytes
    (covers chunked/missing/misleading headers). Buffers up to max_bytes+1 to allow
    replay to downstream app when within limit.
    """

    def __init__(self, app, max_body_bytes: int | None = None):
        self.app = app
        configured = max_body_bytes if max_body_bytes is not None else getattr(settings, "MAX_REQUEST_BODY_BYTES", 1_048_576)
        self.max_body_bytes = max(0, int(configured))

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        max_bytes = self.max_body_bytes
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except (TypeError, ValueError):
                log_security_event(
                    "request.invalid_content_length",
                    severity="warning",
                    path=scope.get("path", ""),
                    method=scope.get("method", ""),
                    client_ip=(scope.get("client") or ["unknown"])[0],
                )
                await self._drain_and_send_error(scope, receive, send, max_bytes, status_code=400, detail="Invalid Content-Length header")
                return
            if length < 0:
                log_security_event(
                    "request.invalid_content_length",
                    severity="warning",
                    path=scope.get("path", ""),
                    method=scope.get("method", ""),
                    client_ip=(scope.get("client") or ["unknown"])[0],
                )
                await self._drain_and_send_error(scope, receive, send, max_bytes, status_code=400, detail="Invalid Content-Length header")
                return
            if length > max_bytes:
                log_security_event(
                    "request.too_large",
                    severity="warning",
                    path=scope.get("path", ""),
                    method=scope.get("method", ""),
                    client_ip=(scope.get("client") or ["unknown"])[0],
                    content_length=length,
                    max_bytes=max_bytes,
                )
                await self._drain_and_send_error(scope, receive, send, max_bytes)
                return

        body = b""
        more_body = True
        received = 0
        while more_body:
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                received += len(chunk)
                if received > max_bytes:
                    log_security_event(
                        "request.too_large",
                        severity="warning",
                        path=scope.get("path", ""),
                        method=scope.get("method", ""),
                        client_ip=(scope.get("client") or ["unknown"])[0],
                        max_bytes=max_bytes,
                        streaming=True,
                    )
                    # Drain remaining body to avoid connection issues on keep-alive.
                    more_body = bool(message.get("more_body", False))
                    while more_body:
                        drain = await receive()
                        if drain.get("type") != "http.request":
                            break
                        more_body = bool(drain.get("more_body", False))
                    await self._send_error(scope, receive, send, max_bytes)
                    return
                body += chunk
                more_body = bool(message.get("more_body", False))
            elif message.get("type") == "http.disconnect":
                return
            else:
                # Unexpected message type; stop safely.
                more_body = False

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if replayed:
                # After body replay, forward disconnect/other messages.
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay_receive, send)

    async def _drain_and_send_error(self, scope, receive, send, max_bytes: int, status_code: int = 413, detail: str = "Request payload too large"):
        # Best-effort drain to reduce keep-alive connection issues after early reject.
        try:
            more_body = True
            while more_body:
                message = await receive()
                if message.get("type") != "http.request":
                    break
                more_body = bool(message.get("more_body", False))
        except Exception:
            pass
        await self._send_error(scope, receive, send, max_bytes, status_code=status_code, detail=detail)

    async def _send_error(self, scope, receive, send, max_bytes: int, status_code: int = 413, detail: str = "Request payload too large"):
        payload = {"detail": detail}
        if status_code == 413:
            payload["max_bytes"] = max_bytes
        response = JSONResponse(status_code=status_code, content=payload)
        await response(scope, receive, send)
