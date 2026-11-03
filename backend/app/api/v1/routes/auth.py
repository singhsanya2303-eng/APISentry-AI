"""
Authentication API Routes — End-user login, token issuance, profile, and protected resource access.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.core.config import settings
from app.core.security import (
    authenticate_user,
    create_access_token,
    require_jwt_auth,
)
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserProfileResponse,
)

router = APIRouter(prefix="/auth", tags=["User Authentication"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="End-User Authentication & JWT Token Issuance",
    responses={
        401: {"description": "Invalid username or password"},
    },
)
def login(credentials: LoginRequest) -> TokenResponse:
    """
    Authenticate an end-user with credentials and issue an RFC 7519 HS256-signed JWT token.
    """
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expires_in_seconds = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    token = create_access_token(
        subject=user["actor_id"],
        extra_claims={
            "username": user["username"],
            "role": user.get("role", "user"),
        },
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        actor_id=user["actor_id"],
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get Authenticated User Profile",
    responses={
        401: {"description": "Missing, invalid, or expired JWT token"},
    },
)
def get_current_user_profile(
    user_payload: dict = Depends(require_jwt_auth),
) -> UserProfileResponse:
    """
    Return profile metadata for the authenticated actor.
    Requires a valid Bearer JWT access token.
    """
    return UserProfileResponse(
        username=user_payload.get("username", "unknown"),
        actor_id=user_payload["sub"],
        role=user_payload.get("role", "user"),
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
