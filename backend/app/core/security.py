import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

# ---------------------------------------------------------------------------
# API Key Authentication (Existing System-to-System Mechanism)
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
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    if not api_key or not secrets.compare_digest(
        api_key,
        configured_key,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


# ---------------------------------------------------------------------------
# Password Hashing & Verification (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

DEFAULT_PBKDF2_ITERATIONS = 100_000


def hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
    """
    Securely hash a plain password using PBKDF2-HMAC-SHA256 with a unique random salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a stored PBKDF2-HMAC-SHA256 hash in constant time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
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
    except Exception:
        return False


# ---------------------------------------------------------------------------
# In-Memory End-User Store (Preserves Live Database Integrity)
# ---------------------------------------------------------------------------

_USER_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_user(
    username: str,
    password: str,
    actor_id: Optional[str] = None,
    role: str = "user",
) -> Dict[str, Any]:
    """Register or update an end-user with a securely hashed password."""
    norm_username = username.strip().lower()
    user_actor_id = actor_id or f"actor_{norm_username}"
    user_record = {
        "username": norm_username,
        "actor_id": user_actor_id,
        "hashed_password": hash_password(password),
        "role": role,
    }
    _USER_REGISTRY[norm_username] = user_record
    return user_record


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by username."""
    if not username:
        return None
    return _USER_REGISTRY.get(username.strip().lower())


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Validate username and password credentials against registered users.
    Returns user record if credentials are valid; otherwise None.
    """
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def seed_demo_user() -> None:
    """Register the explicitly configured local demo user when demo mode is enabled."""
    if not settings.is_demo_auth_enabled:
        return
    demo_password = settings.DEMO_PASSWORD
    if not demo_password:
        return
    register_user(
        username=settings.DEMO_USERNAME,
        password=demo_password,
        actor_id=f"actor_{settings.DEMO_USERNAME.strip().lower()}",
        role="user",
    )

# ---------------------------------------------------------------------------
# RFC 7519 JSON Web Token (JWT) Engine — HS256 Standard Implementation
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string without trailing padding '='."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode URL-safe base64 string with restored '=' padding."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate an RFC 7519 HS256-signed JWT access token.

    Claims:
    - sub: Verified actor identity
    - iat: Issued-at UTC timestamp
    - exp: Expiration UTC timestamp
    - extra_claims: Optional additional non-sensitive context
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


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Validate and decode an RFC 7519 HS256 JWT access token.

    Guarantees:
    - Validates 3 dot-delimited segments.
    - Validates algorithm is strictly HS256 (rejects 'none' and other algs).
    - Verifies HMAC signature in constant time against settings.JWT_SECRET_KEY.
    - Enforces expiration (exp) and presence of subject (sub).
    - Raises ValueError with explicit reason on any failure.
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

    return payload


# ---------------------------------------------------------------------------
# FastAPI Dependency for Protected End-User Routes
# ---------------------------------------------------------------------------

oauth2_bearer = HTTPBearer(auto_error=False)


async def require_jwt_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_bearer),
) -> Dict[str, Any]:
    """
    Authenticate end-users via Bearer JWT token.

    Workflow:
    1. Extracts Bearer token from the HTTP Authorization header.
    2. Validates token signature, structure, and expiration.
    3. Attaches verified user identity directly to request.state.actor_id.
    4. Attaches payload to request.state.user for downstream middleware and route consumption.
    5. Rejects missing, invalid, expired, or tampered tokens with HTTP 401 Unauthorized.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except ValueError as exc:
        error_msg = str(exc)
        if "expired" in error_msg.lower():
            detail = "Authentication token has expired"
        else:
            detail = "Invalid or tampered authentication token"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    verified_actor = str(payload["sub"]).strip()

    # Explicitly attach verified actor identity to server-side request state
    request.state.actor_id = verified_actor
    request.state.user_id = verified_actor
    request.state.user = payload

    return payload
