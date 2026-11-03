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
from starlette.responses import Response
from app.core.config import settings
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
