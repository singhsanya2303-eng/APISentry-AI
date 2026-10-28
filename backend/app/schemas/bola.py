from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ResourceIdentifier(BaseModel):
    """
    Represents a candidate object/resource reference extracted from an API URI path.
    Note: A candidate reference indicates object access context, NOT a vulnerability decision.
    """
    resource_type: str = Field(..., description="Collection or resource type name (e.g. 'users', 'orders')")
    resource_id: str = Field(..., description="Raw string value of extracted resource identifier")
    position: int = Field(..., description="0-based segment index in URI path")
    is_numeric: bool = Field(..., description="True if resource_id is purely numeric")
    is_uuid: bool = Field(..., description="True if resource_id matches standard UUID format")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score of resource extraction (0.0 - 1.0)")

    model_config = ConfigDict(from_attributes=True)


class ResourceAccessEvent(BaseModel):
    """
    Derived security analysis schema pairing API request context with candidate object references.
    Does NOT store sensitive credentials (passwords, tokens, cookies, auth headers).
    """
    request_id: str = Field(..., description="Unique correlation ID for request tracing")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of API request"
    )
    method: str = Field(..., description="HTTP method (e.g. GET, POST, PUT, DELETE)")
    raw_path: str = Field(..., description="Original raw URI path")
    client_ip: str = Field(..., description="Client IP address")
    status_code: int = Field(..., description="HTTP response status code")
    normalized_endpoint: str = Field(..., description="Path template with IDs replaced by placeholders (e.g. /users/{user_id})")
    actor_id: Optional[str] = Field(default=None, description="Non-sensitive actor/user identity when safely available")
    primary_resource: Optional[ResourceIdentifier] = Field(default=None, description="Primary (innermost) target resource identifier")
    parent_resource: Optional[ResourceIdentifier] = Field(default=None, description="Parent resource identifier if nested")
    extracted_resources: List[ResourceIdentifier] = Field(default_factory=list, description="All candidate resource references in path")
    has_object_reference: bool = Field(..., description="True if at least one candidate object reference was extracted")

    model_config = ConfigDict(from_attributes=True)


class DetectionVerdict(str, Enum):
    """Verdict classification for BOLA/IDOR analysis."""
    NO_SUSPICIOUS_BEHAVIOR = "no_suspicious_behavior"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SUSPICIOUS_BOLA_CANDIDATE = "suspicious_bola_candidate"


class BolaEvidence(BaseModel):
    """Structured evidence for a suspicious BOLA/IDOR candidate pattern."""
    actor_id: str = Field(..., description="Non-sensitive actor identity associated with access pattern")
    resource_type: str = Field(..., description="Target collection or resource type name")
    normalized_endpoint: str = Field(..., description="Normalized API endpoint template")
    accessed_object_ids: List[str] = Field(..., description="List of distinct object IDs accessed by actor")
    distinct_object_count: int = Field(..., description="Number of distinct object IDs accessed")
    is_sequential: bool = Field(..., description="True if accessed numeric IDs form a sequential pattern")
    successful_access_count: int = Field(0, description="Count of requests returning 2xx status codes")
    redirect_access_count: int = Field(0, description="Count of requests returning 3xx status codes")
    client_error_count: int = Field(0, description="Count of requests returning 4xx status codes")
    server_error_count: int = Field(0, description="Count of requests returning 5xx status codes")
    request_ids: List[str] = Field(default_factory=list, description="Request correlation IDs involved")
    timestamps: List[datetime] = Field(default_factory=list, description="Timestamps of involved requests")
    methods: List[str] = Field(default_factory=list, description="HTTP methods used")
    status_codes: List[int] = Field(default_factory=list, description="Response status codes observed")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Evidence strength/confidence score")
    explanation: str = Field(..., description="Explainable natural-language evidence summary")

    model_config = ConfigDict(from_attributes=True)


class BolaDetectionResult(BaseModel):
    """Overall BOLA/IDOR analysis output wrapping verdict and evidence."""
    verdict: DetectionVerdict = Field(..., description="Overall detection verdict")
    evidences: List[BolaEvidence] = Field(default_factory=list, description="List of evidence entries for suspicious patterns")
    analyzed_event_count: int = Field(..., description="Total number of events analyzed")
    explanation: str = Field(..., description="Summary explanation of detection results")

    model_config = ConfigDict(from_attributes=True)
