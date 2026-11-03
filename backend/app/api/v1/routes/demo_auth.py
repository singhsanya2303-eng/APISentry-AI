"""
Demo Authentication Route — Local Development & Demonstration Only.

SECURITY CONTRACT:
  - STRICTLY FOR LOCAL DEMO / DEVELOPMENT TESTING.
  - Never enabled in production environments.
  - Returns HTTP 401 Unauthorized for deliberately invalid credentials.
  - Returns HTTP 200 OK for valid demo credentials ("demo_user" / "demo_password123").
  - Never logs or stores submitted passwords.
  - Handled by RequestLoggingMiddleware for traffic logging and persistence.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(tags=["Demo / Development Only"])


class DemoLoginRequest(BaseModel):
    username: str = Field(..., description="Demo username", examples=["demo_user"])
    password: str = Field(..., description="Demo password", examples=["wrong_password"])


class DemoLoginResponse(BaseModel):
    message: str
    authenticated: bool
    demo_mode: bool = True


@router.post(
    "/login",
    response_model=DemoLoginResponse,
    responses={
        401: {"description": "Invalid demo credentials"},
    },
    summary="Local Demo-Only Authentication Endpoint",
    description=(
        "Simulated login endpoint for testing brute-force security analysis. "
        "Returns HTTP 401 for invalid credentials and HTTP 200 for valid demo credentials. "
        "Strictly intended for local development demonstrations."
    ),
)
def demo_login(credentials: DemoLoginRequest):
    """
    Handle demo authentication attempts.
    Deliberately validates against hardcoded demo test credentials.
    """
    # Hardcoded local demo credentials
    if credentials.username == "demo_user" and credentials.password == "demo_password123":
        return DemoLoginResponse(
            message="Demo authentication successful",
            authenticated=True,
            demo_mode=True,
        )

    # Deliberately invalid demo credentials trigger HTTP 401
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials for demo authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )
