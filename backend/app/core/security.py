import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Set

import bcrypt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security_events import log_security_event
from app.db.session import get_db

logger = logging.getLogger("apisentry.security")

# ---------------------------------------------------------------------------
# API Key Authentication (System-to-System Mechanism)
# ---------------------------------------------------------------------------

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def require_api_key(
    api_key: str | None = Security(api_key_header),
) -> None:
    """Enforce server-to-server static API key authentication for protected security routes."""
    configured_key = settings.API_KEY

    # Never allow requests if the server key is not configured.
    if not configured_key:
        log_security_event("auth.api_key_not_configured", severity="error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    if not api_key or not secrets.compare_digest(
        api_key,
        configured_key,
    ):
        log_security_event("auth.api_key_rejected", severity="warning")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ---------------------------------------------------------------------------
# Password Hashing & Verification (Bcrypt with PBKDF2 backward compatibility)
# ---------------------------------------------------------------------------

DEFAULT_PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """
    Securely hash a plain password using bcrypt with a 12-round salt.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    pwd_bytes = password.encode("utf-8")
    if len(pwd_bytes) > 72:
        raise ValueError("Password exceeds maximum allowed length of 72 bytes")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a stored bcrypt or PBKDF2-HMAC-SHA256 hash in constant time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8"),
            )
        elif hashed_password.startswith("pbkdf2_sha256$"):
            parts = hashed_password.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            expected_hash = parts[3]

            derived = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            return secrets.compare_digest(derived.hex(), expected_hash)
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# In-Memory Fallback Registry (Backward-Compatible Testing Layer)
# ---------------------------------------------------------------------------

_USER_REGISTRY: Dict[str, Dict[str, Any]] = {}
# Hash -> expiry epoch seconds. Raw token hashes only; raw tokens never stored.
_REVOKED_TOKEN_EXPIRY: Dict[str, int] = {}


class _RevokedTokenSet(set):
    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        _REVOKED_TOKEN_EXPIRY.clear()


# Backward-compatible name retained for tests/introspection; contains hashes.
_REVOKED_TOKENS: Set[str] = _RevokedTokenSet()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _cleanup_revoked_tokens(now_ts: Optional[int] = None) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp()) if now_ts is None else int(now_ts)
    expired = [h for h, exp in _REVOKED_TOKEN_EXPIRY.items() if exp <= now_ts]
    for h in expired:
        _REVOKED_TOKEN_EXPIRY.pop(h, None)
        _REVOKED_TOKENS.discard(h)


def _jwt_exp_unverified(token: str) -> int:
    """Best-effort exp extraction for revocation bookkeeping. No trust decision."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return int((datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            return int(exp)
    except Exception:
        pass
    return int((datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())


def _is_revocation_store_missing(exc: Exception) -> bool:
    """True when revocation persistence store is not deployed (migration 0004 unapplied)."""
    msg = str(exc).lower()
    if "revoked_tokens" in msg and (
        "no such table" in msg
        or "does not exist" in msg
        or "undefinedtable" in msg
        or "relation" in msg
    ):
        return True
    try:
        from sqlalchemy.exc import OperationalError, ProgrammingError

        if isinstance(exc, (OperationalError, ProgrammingError)):
            if "revoked_tokens" in msg and ("no such table" in msg or "does not exist" in msg):
                return True
    except Exception:
        pass
    return False


def revoke_token(token: str, db: Optional[Session] = None) -> None:
    """Revoke a JWT token for logout/session invalidation.

    Stores SHA-256 hash + expiry in memory and, when possible, in the
    revoked_tokens table for restart durability. DB failures fall back to
    in-memory revocation so logout does not silently succeed without local effect.
    """
    if not token or not isinstance(token, str):
        return
    raw = token.strip()
    if not raw:
        return
    token_h = _token_hash(raw)
    exp_ts = _jwt_exp_unverified(raw)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    _cleanup_revoked_tokens(now_ts)
    _REVOKED_TOKEN_EXPIRY[token_h] = exp_ts
    _REVOKED_TOKENS.add(token_h)

    if db is None:
        return
    try:
        from app.models.revoked_token import RevokedToken

        existing = db.query(RevokedToken).filter(RevokedToken.token_hash == token_h).first()
        if existing is None:
            db.add(
                RevokedToken(
                    token_hash=token_h,
                    expires_at=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
                    revoked_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        else:
            # Keep earliest/known expiry; ensure row exists.
            db.commit()
    except Exception:
        db.rollback()
        logger.warning("revoked token DB persistence failed; in-memory revocation remains active", exc_info=True)


def is_token_revoked(token: str, db: Optional[Session] = None) -> bool:
    """Check whether token has been revoked. Fails closed on malformed input."""
    if not token or not isinstance(token, str):
        return True
    raw = token.strip()
    if not raw:
        return True
    token_h = _token_hash(raw)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    _cleanup_revoked_tokens(now_ts)
    exp_ts = _REVOKED_TOKEN_EXPIRY.get(token_h)
    if exp_ts is not None and exp_ts > now_ts:
        return True
    # Expired in-memory entry can be removed.
    if exp_ts is not None:
        _REVOKED_TOKEN_EXPIRY.pop(token_h, None)
        _REVOKED_TOKENS.discard(token_h)

    # Legacy/backcompat: tests or older code may have added raw token strings.
    if raw in _REVOKED_TOKENS and raw != token_h:
        return True

    if db is None:
        return token_h in _REVOKED_TOKENS
    try:
        from app.models.revoked_token import RevokedToken

        row = (
            db.query(RevokedToken)
            .filter(RevokedToken.token_hash == token_h)
            .filter(RevokedToken.expires_at > datetime.now(timezone.utc))
            .first()
        )
        if row is not None:
            # Warm in-memory cache for subsequent checks.
            row_exp = int(row.expires_at.timestamp()) if row.expires_at.tzinfo else int(row.expires_at.replace(tzinfo=timezone.utc).timestamp())
            _REVOKED_TOKEN_EXPIRY[token_h] = row_exp
            _REVOKED_TOKENS.add(token_h)
            return True
        return False
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            logger.debug("revoked token DB rollback failed after lookup error", exc_info=True)
        if _is_revocation_store_missing(exc):
            # Migration 0004/file-only revocation store not deployed. Fall back to
            # in-memory revocation state for demo/local compatibility, but do not
            # claim durable or multi-worker revocation guarantees.
            logger.warning(
                "revoked token store unavailable (migration not deployed); using in-memory revocation state only",
                exc_info=True,
            )
            return token_h in _REVOKED_TOKENS
        logger.warning("revoked token DB check failed; failing closed", exc_info=True)
        return True


def register_user(
    username: str,
    password: str,
    actor_id: Optional[str] = None,
    role: str = "user",
    email: Optional[str] = None,
) -> Dict[str, Any]:
    """Register or update an end-user in the registry layer."""
    norm_username = username.strip().lower()
    user_actor_id = actor_id or f"actor_{norm_username}"
    user_record = {
        "username": norm_username,
        "email": email or f"{norm_username}@apisentry.local",
        "actor_id": user_actor_id,
        "hashed_password": hash_password(password),
        "role": role,
        "is_active": True,
    }
    _USER_REGISTRY[norm_username] = user_record
    return user_record


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record from memory registry by username."""
    if not username:
        return None
    return _USER_REGISTRY.get(username.strip().lower())


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Validate username and password credentials against memory registry.
    """
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def seed_demo_user(db: Optional[Session] = None) -> None:
    """Register the explicitly configured local demo user when demo mode is enabled."""
    if not settings.is_demo_auth_enabled:
        return
    demo_password = settings.DEMO_PASSWORD
    if not demo_password:
        return
    norm_demo = settings.DEMO_USERNAME.strip().lower()

    # Always ensure in-memory registry contains demo user
    register_user(
        username=norm_demo,
        password=demo_password,
        actor_id=f"actor_{norm_demo}",
        role="analyst",
        email=f"{norm_demo}@apisentry.local",
    )

    # If DB session provided, ensure user exists in PostgreSQL
    if db is not None:
        from app.models.user import User
        from app.services.user_service import get_user_by_username as get_db_user

        existing = get_db_user(db, norm_demo)
        if not existing:
            demo_user = User(
                username=norm_demo,
                email=f"{norm_demo}@apisentry.local",
                hashed_password=hash_password(demo_password),
                role="analyst",
                is_active=True,
            )
            db.add(demo_user)
            db.commit()


# ---------------------------------------------------------------------------
# RFC 7519 JSON Web Token (JWT) Engine — HS256 Standard Implementation
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string without trailing padding '='."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode a canonical, unpadded Base64URL segment.

    JWT segments are canonical Base64URL without padding. Rejecting padded,
    malformed, or noncanonical spellings prevents the same decoded bytes from
    having multiple compact-serialized representations, while remaining fully
    compatible with tokens produced by ``_b64url_encode``.
    """
    if not isinstance(data, str) or not data:
        raise ValueError("Empty Base64URL segment")
    if "=" in data:
        raise ValueError("Base64URL segments must not be padded")
    rem = len(data) % 4
    if rem == 1:
        raise ValueError("Invalid Base64URL segment length")
    try:
        decoded = base64.urlsafe_b64decode((data + "=" * ((4 - rem) % 4)).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"Malformed Base64URL segment: {exc}") from exc
    if _b64url_encode(decoded) != data:
        raise ValueError("Noncanonical Base64URL segment")
    return decoded


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate an RFC 7519 HS256-signed JWT access token.
    """
    if not subject or not str(subject).strip():
        raise ValueError("JWT subject claim (sub) cannot be empty")

    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        exp = now + expires_delta
    else:
        exp = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(subject).strip(),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = settings.JWT_SECRET_KEY.encode("utf-8")
    signature = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str, db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Validate and decode an RFC 7519 HS256 JWT access token.

    Revocation is checked after signature and expiry validation so only
    authentic, unexpired tokens incur revocation-store lookups.
    """
    if not token or not isinstance(token, str):
        raise ValueError("Invalid token format")

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT token: must have exactly 3 segments")

    header_b64, payload_b64, sig_b64 = parts

    # 1. Parse and validate header
    try:
        header_data = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Malformed JWT header: {exc}") from exc

    if not isinstance(header_data, dict):
        raise ValueError("JWT header must be a JSON object")

    if header_data.get("alg") != "HS256":
        raise ValueError(f"Unsupported algorithm '{header_data.get('alg')}': only HS256 is accepted")

    # 2. Verify HMAC-SHA256 signature in constant time
    try:
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise ValueError(f"Malformed JWT signature: {exc}") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = settings.JWT_SECRET_KEY.encode("utf-8")
    expected_sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()

    if not secrets.compare_digest(provided_sig, expected_sig):
        raise ValueError("Invalid JWT signature: token has been tampered with")

    # 3. Parse and validate payload
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Malformed JWT payload: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be a JSON object")

    if "sub" not in payload or not str(payload["sub"]).strip():
        raise ValueError("JWT payload missing required 'sub' claim")

    if "exp" not in payload:
        raise ValueError("JWT payload missing required 'exp' claim")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp_ts = int(payload["exp"])
    if now_ts >= exp_ts:
        raise ValueError("JWT token has expired")

    if is_token_revoked(token, db=db):
        raise ValueError("Authentication token has been revoked")

    return payload


# ---------------------------------------------------------------------------
# FastAPI Dependencies for Protected End-User Routes & RBAC
# ---------------------------------------------------------------------------

oauth2_bearer = HTTPBearer(auto_error=False)


async def require_jwt_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_bearer),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Authenticate end-users via Bearer JWT token.
    Attaches verified identity to request.state.actor_id and request.state.user.
    """
    if not credentials or not credentials.credentials:
        log_security_event(
            "auth.missing_credentials",
            severity="warning",
            path=str(request.url.path),
            method=request.method,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token, db=db)
    except ValueError as exc:
        error_msg = str(exc)
        if "expired" in error_msg.lower():
            detail = "Authentication token has expired"
            event = "auth.token_expired"
        elif "revoked" in error_msg.lower():
            detail = "Authentication token has been revoked"
            event = "auth.token_revoked"
        else:
            detail = "Invalid or tampered authentication token"
            event = "auth.token_invalid"
        log_security_event(
            event,
            severity="warning",
            path=str(request.url.path),
            method=request.method,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    verified_actor = str(payload["sub"]).strip()

    request.state.actor_id = verified_actor
    request.state.user_id = verified_actor
    request.state.user = payload

    return payload


def _build_claims_user(payload: Dict[str, Any]) -> SimpleNamespace:
    """
    Build a lightweight authenticated principal from a verified JWT payload.

    The database remains the source of truth for persistent users; this fallback
    only applies to tokens issued by the in-memory compatibility registry or to
    signed tokens whose subject does not have a database row (for example, test
    fixtures and pre-persistence identities). No claim is trusted until the JWT
    signature and expiry have already been validated by ``require_jwt_auth``.
    """
    from app.models.user import ALLOWED_ROLES, UserRole

    sub = str(payload.get("sub", "")).strip()
    username = str(payload.get("username") or sub).strip().lower()
    registry_user = _USER_REGISTRY.get(username) if username else None

    actor_id = str(
        payload.get("actor_id")
        or sub
        or (registry_user or {}).get("actor_id")
        or f"user_{username}"
    ).strip()

    role = str(
        (registry_user or {}).get("role")
        or payload.get("role")
        or UserRole.VIEWER.value
    )
    if role not in ALLOWED_ROLES:
        role = UserRole.VIEWER.value

    is_active = bool(
        (registry_user or {}).get("is_active", payload.get("is_active", True))
    )

    email = (registry_user or {}).get("email") or payload.get("email")
    if not email:
        email = sub if "@" in sub else f"{username or 'user'}@apisentry.local"

    return SimpleNamespace(
        # A claims-only principal has no persistent database identity, even if
        # a legacy token carried a user_id claim. Never expose a database id
        # that was not verified against a users row.
        id=None,
        username=username or actor_id,
        email=str(email),
        hashed_password=(registry_user or {}).get("hashed_password", ""),
        actor_id=actor_id,
        role=role,
        is_active=is_active,
        is_authenticated=is_active,
        identity=actor_id,
    )


def _normalize_identity_claim(value: Any) -> Optional[str]:
    """Normalize a string identity claim; blank values are treated as absent."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return normalized or None


def _normalize_user_id_claim(value: Any) -> Optional[int]:
    """Return a usable database id from a claim, or None when contradictory."""
    if value is None or isinstance(value, bool):
        return None
    try:
        normalized = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return normalized if normalized > 0 else None


def _identity_claims_match_user(payload: Dict[str, Any], user: Any) -> bool:
    """Ensure verified token claims agree with the candidate database user."""
    sub = _normalize_identity_claim(payload.get("sub"))
    username = _normalize_identity_claim(payload.get("username"))

    subject_identifiers = {
        _normalize_identity_claim(user.username),
        _normalize_identity_claim(user.email),
        _normalize_identity_claim(getattr(user, "actor_id", None)),
    }
    subject_identifiers.discard(None)
    if sub and sub not in subject_identifiers:
        return False

    username_identifiers = {
        _normalize_identity_claim(user.username),
        _normalize_identity_claim(user.email),
    }
    username_identifiers.discard(None)
    if username and username not in username_identifiers:
        return False
    return True


def _reject_contradictory_claims(verified_actor: str) -> None:
    """Fail closed when identity claims cannot be reconciled with the database."""
    log_security_event(
        "auth.contradictory_identity_claims",
        severity="warning",
        actor_id=verified_actor,
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Contradictory identity claims",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_bearer),
):
    """
    Retrieve the authenticated principal, preferring the persistent database.

    Enforces active account status and never trusts client-supplied identity
    headers or query parameters; identity comes only from the verified JWT.
    """
    payload = await require_jwt_auth(request, credentials, db=db)
    verified_actor = str(payload["sub"]).strip()
    sub = _normalize_identity_claim(verified_actor)
    username = _normalize_identity_claim(payload.get("username"))
    raw_user_id = payload.get("user_id")
    user_id = None

    from app.models.user import User

    if raw_user_id is not None:
        user_id = _normalize_user_id_claim(raw_user_id)
        if user_id is None:
            _reject_contradictory_claims(verified_actor)

    user = None
    if user_id is not None:
        user = db.query(User).filter(User.id == user_id).first()
        if user is not None and not _identity_claims_match_user(payload, user):
            _reject_contradictory_claims(verified_actor)

    if user is None:
        candidate = None
        if username:
            candidate = db.query(User).filter(User.username == username).first()
        if candidate is None and sub:
            candidate = db.query(User).filter(User.email == sub).first()

        if candidate is not None:
            # A user_id claim that disagrees with the username/email-resolved
            # row is a confused-deputy signal, not something to silently ignore.
            if user_id is not None and candidate.id != user_id:
                _reject_contradictory_claims(verified_actor)
            if not _identity_claims_match_user(payload, candidate):
                _reject_contradictory_claims(verified_actor)
            user = candidate

    # Verified-JWT fallback for registry-backed and pre-persistence identities.
    # No database id or database role is inherited here.
    if user is None:
        user = _build_claims_user(payload)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Attach the verified principal to request state for downstream middleware.
    # The actor ID always comes from the signed token, never from client headers.
    request.state.user = user
    request.state.actor_id = verified_actor

    return user


async def get_current_active_user(
    current_user=Depends(get_current_user),
):
    """Ensure current user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return current_user


class RequireRole:
    """Server-side RBAC dependency factory."""

    def __init__(self, allowed_roles: Sequence[str]):
        self.allowed_roles = set(allowed_roles)

    async def __call__(
        self,
        current_user=Depends(get_current_active_user),
    ):
        if current_user.role not in self.allowed_roles:
            log_security_event(
                "auth.rbac_denied",
                severity="warning",
                role=str(getattr(current_user, "role", "unknown")),
                required_roles=sorted(self.allowed_roles),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{current_user.role}'. Required: {', '.join(sorted(self.allowed_roles))}",
            )
        return current_user


require_admin = RequireRole(["admin"])
require_analyst = RequireRole(["admin", "analyst"])
require_viewer = RequireRole(["admin", "analyst", "viewer"])


async def require_analyst_or_api_key(
    request: Request,
    db: Session = Depends(get_db),
    api_key: str | None = Security(api_key_header),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_bearer),
) -> None:
    """
    Dual authentication dependency for security analysis routes:
    1. Validates static server-to-server X-API-Key if present.
    2. Alternatively validates JWT Bearer token with analyst or admin role.
    3. Rejects viewer role with HTTP 403 Forbidden.
    4. Rejects unauthenticated requests with HTTP 401 Unauthorized.
    """
    configured_key = settings.API_KEY

    # 1. Check API Key
    if api_key:
        if not configured_key:
            log_security_event("auth.api_key_not_configured", severity="error", path=str(request.url.path))
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured",
            )
        if secrets.compare_digest(api_key, configured_key):
            return
        log_security_event("auth.api_key_rejected", severity="warning", path=str(request.url.path))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. Check JWT Bearer
    if credentials and credentials.credentials:
        user = await get_current_user(request, db=db, credentials=credentials)
        if user.role not in {"admin", "analyst"}:
            log_security_event(
                "auth.rbac_denied",
                severity="warning",
                path=str(request.url.path),
                role=str(getattr(user, "role", "unknown")),
                required_roles=["admin", "analyst"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{user.role}'. Required: admin or analyst",
            )
        return

    # 3. Neither provided
    if configured_key:
        log_security_event(
            "auth.missing_credentials",
            severity="warning",
            path=str(request.url.path),
            method=request.method,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key or authorization token",
            headers={"WWW-Authenticate": "Bearer, ApiKey"},
        )
    log_security_event("auth.not_configured", severity="error", path=str(request.url.path))
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="API authentication is not configured",
    )
