"""
Authentication and User RBAC schemas for registration, login, token issuance, and profiles.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRole(str, Enum):
    """Controlled user authorization roles."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class LoginRequest(BaseModel):
    """Payload for authenticating an end-user."""
    username: str = Field(..., min_length=1, max_length=255, description="Email address or username", examples=["alice@example.com"])
    password: str = Field(..., min_length=1, max_length=72, description="User password", examples=["AlicePassword123!"])


class UserRegisterRequest(BaseModel):
    """Payload for public self-registration.

    Public registration is always provisioned as a viewer account. Any
    client-supplied role field is ignored for backward compatibility and never
    influences the persisted or returned role.
    """

    model_config = ConfigDict(extra="ignore")

    email: EmailStr = Field(
        ...,
        description="Normalized unique email address",
        examples=["analyst@apisentry.ai"],
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Unique username identifier",
        examples=["analyst_jane"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=72,
        description="Plaintext password to be securely hashed with bcrypt",
        examples=["SecurePass123!"],
    )


class UserResponse(BaseModel):
    """Public user attributes."""
    id: int = Field(..., description="Unique persistent user ID")
    email: str = Field(..., description="Normalized user email")
    username: str = Field(..., description="Normalized username")
    role: str = Field(..., description="User role (admin, analyst, viewer)")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Registration timestamp (UTC)")
    actor_id: str = Field(..., description="Correlated actor ID")

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """JWT access token response model."""
    access_token: str = Field(..., description="RFC 7519 HS256-signed JWT access token")
    token_type: str = Field(default="bearer", description="Token type (Bearer)")
    expires_in: int = Field(..., description="Validity lifetime in seconds")
    actor_id: str = Field(..., description="Verified actor identifier corresponding to authenticated identity")
    user: Optional[UserResponse] = Field(default=None, description="Authenticated user summary")


class UserProfileResponse(BaseModel):
    """Profile attributes of the authenticated actor."""
    username: str = Field(..., description="Account username")
    email: Optional[str] = Field(default=None, description="Account email")
    actor_id: str = Field(..., description="Unique persistent actor identifier")
    role: str = Field(default=UserRole.VIEWER.value, description="Authorization role")
    is_active: bool = Field(default=True, description="Active status")

    model_config = ConfigDict(from_attributes=True)


class UserUpdateRequest(BaseModel):
    """Admin-only payload to update a user's role or active status."""
    role: Optional[UserRole] = Field(default=None, description="Updated role")
    is_active: Optional[bool] = Field(default=None, description="Updated active status")
    password: Optional[str] = Field(default=None, min_length=8, max_length=72, description="Updated password")
