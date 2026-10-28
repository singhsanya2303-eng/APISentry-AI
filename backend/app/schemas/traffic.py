from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class APITrafficLogBase(BaseModel):
    """Base schema for captured API traffic metadata."""
    request_id: str = Field(..., description="Unique correlation ID for request tracing")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of request"
    )
    method: str = Field(..., description="HTTP method (e.g. GET, POST)")
    path: str = Field(..., description="Request URI path")
    query_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized key-value query parameters"
    )
    client_ip: str = Field(..., description="Client IP address")
    user_agent: Optional[str] = Field(default="", description="Client User-Agent string")
    status_code: int = Field(..., description="HTTP response status code")
    response_time_ms: float = Field(..., description="Processing duration in milliseconds")


class APITrafficLogCreate(APITrafficLogBase):
    """Schema for creating a new API traffic log entry."""
    pass


class APITrafficLogResponse(APITrafficLogBase):
    """Schema for returning an API traffic log entry from storage."""
    id: int = Field(..., description="Database primary key")

    model_config = ConfigDict(from_attributes=True)
