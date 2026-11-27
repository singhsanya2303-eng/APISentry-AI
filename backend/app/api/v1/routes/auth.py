"""
Authentication API Routes — User registration, login, token issuance, logout, and profile access.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import enforce_auth_rate_limit
from app.core.security_events import log_security_event
from app.core.security import (
    authenticate_user,
    create_access_token,
    decode_access_token,
    get_current_active_user,
    hash_password,
    oauth2_bearer,
    require_jwt_auth,
    revoke_token,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserProfileResponse,
    UserRegisterRequest,
    UserResponse,
)
from app.services.user_service import (
    create_user,
    get_user_by_identifier,
)

router = APIRouter(prefix="/auth", tags=["User Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    responses={
        201: {"description": "User successfully registered"},
        400: {"description": "Invalid registration payload"},
        403: {"description": "Public registration is disabled"},
        409: {"description": "Email or username already registered"},
    },
)
def register(
    payload: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Register a new user only when public registration is explicitly enabled.

    Registration is disabled by default and always disabled in production. When
    enabled in a non-production environment, accounts are provisioned as
    viewers; client-supplied role values are ignored and never persisted.
    """
    enforce_auth_rate_limit(request, "auth.register")
    if not settings.is_public_registration_enabled:
        log_security_event(
            "auth.registration_disabled",
            severity="warning",
            path=str(request.url.path),
            method=request.method,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled",
        )

    hashed = hash_password(payload.password)

    try:
        user = create_user(
            db=db,
            email=str(payload.email),
            username=payload.username,
            password_hash=hashed,
            role=UserRole.VIEWER.value,
            is_active=True,
        )
    except ValueError as exc:
        msg = str(exc)
        if "already exists" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=msg,
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        ) from exc

    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        actor_id=user.actor_id,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User Authentication & JWT Token Issuance",
    responses={
        401: {"description": "Invalid username or password"},
        403: {"description": "Account is inactive"},
    },
)
def login(
    credentials: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate an end-user with database credentials (or memory registry fallback)
    and issue an RFC 7519 HS256-signed JWT token.
    """
    enforce_auth_rate_limit(request, "auth.login")
    identifier = credentials.username.strip()

    # 1. Check PostgreSQL User model
    user = get_user_by_identifier(db, identifier)

    if user is not None:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )
        if not verify_password(credentials.password, user.hashed_password):
            log_security_event("auth.login_failed", severity="warning", path=str(request.url.path), reason="bad_password")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        actor_id = user.actor_id
        username = user.username
        role = user.role
        token_claims = {
            "user_id": user.id,
            "username": username,
            "role": role,
            "is_active": True,
        }
        user_summary = UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            actor_id=user.actor_id,
        )
    else:
        # 2. Check in-memory registry fallback (preserves unit test fixtures)
        reg_user = authenticate_user(identifier, credentials.password)
        if not reg_user:
            log_security_event("auth.login_failed", severity="warning", path=str(request.url.path), reason="invalid_credentials")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        actor_id = reg_user["actor_id"]
        username = reg_user["username"]
        role = reg_user.get("role", "viewer")
        # Registry-only identities have no database row. Never emit a database
        # user_id claim for them, otherwise a synthetic identity could inherit
        # the role of the unrelated database user with that id.
        token_claims = {
            "username": username,
            "role": role,
            "is_active": True,
        }
        user_summary = None

    expires_in_seconds = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    token = create_access_token(
        subject=actor_id,
        extra_claims=token_claims,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        actor_id=actor_id,
        user=user_summary,
    )


@router.post(
    "/logout",
    summary="Revoke Current JWT Token",
    responses={
        401: {"description": "Missing, invalid, expired, or revoked authentication credentials"},
    },
)
def logout(
    credentials=Depends(oauth2_bearer),
    db: Session = Depends(get_db),
) -> dict:
    """
    Revoke the current JWT access token to invalidate the user session immediately.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        # Revocation is a privileged side effect: never persist it for an
        # unverified bearer string. decode_access_token enforces signature,
        # algorithm, expiry, and revocation policy before we write anything.
        decode_access_token(token, db=db)
    except ValueError as exc:
        message = str(exc).lower()
        if "expired" in message:
            detail = "Authentication token has expired"
            reason = "token_expired"
        elif "revoked" in message:
            detail = "Authentication token has been revoked"
            reason = "token_revoked"
        else:
            detail = "Invalid or tampered authentication token"
            reason = "token_invalid"
        log_security_event(
            "auth.logout_rejected",
            severity="warning",
            reason=reason,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    revoke_token(token, db=db)
    return {"message": "Successfully logged out"}


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get Authenticated User Profile",
    responses={
        401: {"description": "Missing, invalid, or expired JWT token"},
        403: {"description": "Inactive user account"},
    },
)
def get_current_user_profile(
    current_user=Depends(get_current_active_user),
) -> UserProfileResponse:
    """
    Return profile metadata for the authenticated active user.
    """
    return UserProfileResponse(
        username=current_user.username,
        email=getattr(current_user, "email", f"{current_user.username}@apisentry.local"),
        actor_id=current_user.actor_id,
        role=current_user.role,
        is_active=current_user.is_active,
    )


@router.get(
    "/users/{user_id}",
    summary="Protected User Resource Access (BOLA Target Endpoint)",
    responses={
        401: {"description": "Missing, invalid, or expired JWT token"},
    },
)
def get_user_resource(
    user_id: str,
    user_payload: dict = Depends(require_jwt_auth),
) -> dict:
    """
    Access a specific user resource by identifier.
    Protected by JWT authentication; records verified actor identity on the request context
    to enable downstream BOLA/IDOR behavior analysis.
    """
    return {
        "user_id": user_id,
        "accessed_by": user_payload["sub"],
        "status": "active",
    }
