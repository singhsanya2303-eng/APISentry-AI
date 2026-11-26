from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class APITrafficLogBase(BaseModel):
    """Base schema for captured API traffic metadata."""
    request_id: str = Field(
        ..., min_length=1, max_length=100,
        description="Unique correlation ID for request tracing",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of request"
    )
    method: str = Field(
        ..., min_length=1, max_length=10,
        description="HTTP method (e.g. GET, POST)",
    )
    path: str = Field(
        ..., min_length=1, max_length=500,
        description="Request URI path",
    )
    query_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized key-value query parameters"
    )
    client_ip: str = Field(
        ..., min_length=1, max_length=45,
        description="Client IP address",
    )
    user_agent: Optional[str] = Field(
        default="", max_length=500,
        description="Client User-Agent string",
    )
    status_code: int = Field(
        ..., ge=100, le=599,
        description="HTTP response status code",
    )
    response_time_ms: float = Field(
        ..., ge=0,
        description="Processing duration in milliseconds",
    )
    actor_id: Optional[str] = Field(
        default=None, min_length=1, max_length=100,
        description="Verified actor/user identity when authenticated",
    )


class APITrafficLogCreate(APITrafficLogBase):
    """Schema for creating a new API traffic log entry."""
    pass


class APITrafficLogResponse(APITrafficLogBase):
    """Schema for returning an API traffic log entry from storage."""
    id: int = Field(..., description="Database primary key")

    model_config = ConfigDict(from_attributes=True)
