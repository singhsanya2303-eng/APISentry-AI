"""
Authentication schemas for end-user login, token issuance, and user profiles.
"""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Payload for authenticating an end-user."""
    username: str = Field(..., description="User account identifier", examples=["alice"])
    password: str = Field(..., description="User plain password", examples=["AlicePassword123!"])


class TokenResponse(BaseModel):
    """JWT access token response model."""
    access_token: str = Field(..., description="RFC 7519 HS256-signed JWT access token")
    token_type: str = Field(default="bearer", description="Token type (Bearer)")
    expires_in: int = Field(..., description="Validity lifetime in seconds")
    actor_id: str = Field(..., description="Verified actor identifier corresponding to authenticated identity")


class UserProfileResponse(BaseModel):
    """Public profile attributes of the authenticated actor."""
    username: str = Field(..., description="Account username")
    actor_id: str = Field(..., description="Unique persistent actor identifier")
    role: str = Field(default="user", description="Authorization role")
