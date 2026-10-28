
"""
Behavioral Analysis & Normalization Schemas — Module 7, Step 1.

Provides normalized event models and aggregated behavioral feature representations
derived from API traffic metadata and detection signals.

SECURITY CONTRACT:
  - Authorization headers, Bearer tokens, cookies, API keys, passwords,
    and any credential-bearing data are NEVER stored, logged, or exposed.
  - actor_id is OPTIONAL context; client_ip is the primary attribution signal.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict


class BehaviorEvent(BaseModel):
    """
    A single normalized behavioral event capturing API request attributes,
    normalized routing context, resource references, and optional detection metadata.
    """

    request_id: str = Field(
        ..., description="Unique correlation ID for request tracing"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC-aware timestamp of the API request",
    )
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address. Primary attribution signal for behavioral analysis.",
    )
    actor_id: Optional[str] = Field(
        default=None,
        description="Non-sensitive actor identity when safely available (e.g., from safe headers).",
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="User-Agent header value; never store credentials or tokens here.",
    )
    method: str = Field(
        ..., description="HTTP method (e.g. GET, POST, PUT, DELETE)"
    )
    path: str = Field(..., description="Original request URI path")
    normalized_endpoint: str = Field(
        ...,
        description="Normalized path template with resource IDs replaced by placeholders",
    )
    status_code: int = Field(
        ..., description="HTTP response status code"
    )
    resource_type: Optional[str] = Field(
        default=None,
        description="Target resource/collection type (e.g. 'users', 'orders') when extracted",
    )
    resource_id: Optional[str] = Field(
        default=None,
        description="Primary resource/object identifier when extracted",
    )
    detection_source: Optional[str] = Field(
        default=None,
        description="Optional security detection source tag (e.g. 'bola', 'bruteforce', 'rate_anomaly')",
    )
    detection_verdict: Optional[str] = Field(
        default=None,
        description="Optional security detection verdict tag (e.g. 'suspicious_bola_candidate')",
    )

    model_config = ConfigDict(from_attributes=True)


class BehaviorFeatures(BaseModel):
    """
    Deterministic behavioral features extracted for a specific client IP (and optional actor_id).
    Captures traffic volume, resource diversity, error rates, observation window, and detection signals.
    """

    client_ip: str = Field(
        ..., description="Client IP address attributed to this feature set"
    )
    actor_id: Optional[str] = Field(
        default=None,
        description="Representative non-sensitive actor identity if available",
    )
    total_requests: int = Field(
        default=0,
        ge=0,
        description="Total number of requests observed for this client",
    )
    unique_endpoints: int = Field(
        default=0,
        ge=0,
        description="Count of distinct normalized endpoints accessed",
    )
    unique_resource_types: int = Field(
        default=0,
        ge=0,
        description="Count of distinct resource types targeted",
    )
    unique_resource_ids: int = Field(
        default=0,
        ge=0,
        description="Count of distinct resource IDs accessed",
    )
    failed_request_count: int = Field(
        default=0,
        ge=0,
        description="Count of non-successful HTTP responses (status >= 400)",
    )
    successful_request_count: int = Field(
        default=0,
        ge=0,
        description="Count of successful HTTP responses (200 <= status < 300)",
    )
    authentication_failure_count: int = Field(
        default=0,
        ge=0,
        description="Count of HTTP 401 Unauthorized responses",
    )
    rate_anomaly_count: int = Field(
        default=0,
        ge=0,
        description="Number of contributing events flagged with rate anomaly signals",
    )
    bola_candidate_count: int = Field(
        default=0,
        ge=0,
        description="Number of contributing events flagged with BOLA candidate signals",
    )
    brute_force_candidate_count: int = Field(
        default=0,
        ge=0,
        description="Number of contributing events flagged with brute-force candidate signals",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest observed timestamp in UTC",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Latest observed timestamp in UTC",
    )
    observation_window_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Duration between first_seen and last_seen in seconds",
    )

    model_config = ConfigDict(from_attributes=True)


class BehaviorAnalysisResult(BaseModel):
    """
    Overall result of behavioral feature extraction across an analyzed event batch.
    """

    analyzed_event_count: int = Field(
        ..., ge=0,
        description="Total number of traffic / behavioral events analyzed",
    )
    distinct_client_count: int = Field(
        default=0, ge=0,
        description="Number of distinct client IPs identified",
    )
    distinct_actor_count: int = Field(
        default=0, ge=0,
        description="Number of distinct actor identities identified where available",
    )
    client_features: List[BehaviorFeatures] = Field(
        default_factory=list,
        description="Extracted behavioral feature sets grouped per client IP",
    )
    summary: str = Field(
        ..., description="Human-readable summary of behavioral feature extraction",
    )

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Module 7 Step 2: Risk Scoring Schemas
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Categorical risk severity level."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskFactor(BaseModel):
    """Individual behavioral risk factor contributing to the overall risk score."""

    factor_name: str = Field(..., description="Unique machine-readable factor identifier")
    contribution: float = Field(
        ..., ge=0.0, le=100.0,
        description="Score contribution points (0-100)",
    )
    evidence: str = Field(
        ..., description="Deterministic human-readable evidence description"
    )
    triggered: bool = Field(
        default=True, description="Whether this risk factor was activated"
    )

    model_config = ConfigDict(from_attributes=True)


class RiskScoreResult(BaseModel):
    """Final deterministic risk assessment for a single client IP / actor profile."""

    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address attributed to this assessment",
    )
    actor_id: Optional[str] = Field(
        default=None,
        description="Representative non-sensitive actor identity if available",
    )
    risk_score: float = Field(
        ..., ge=0.0, le=100.0,
        description="Calculated bounded risk score (0.0 to 100.0)",
    )
    risk_level: RiskLevel = Field(
        ..., description="Categorical risk level (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    factors: List[RiskFactor] = Field(
        default_factory=list,
        description="List of triggered behavioral risk factors",
    )
    explanation: str = Field(
        ..., description="Human-readable explanation of observed behavioral risk indicators"
    )

    model_config = ConfigDict(from_attributes=True)


class BehaviorRiskAnalysisResponse(BaseModel):
    """Response model for behavioral analysis and deterministic risk scoring."""

    results: List[RiskScoreResult] = Field(
        default_factory=list,
        description="Deterministic list of per-client risk scoring results",
    )
    total_clients: int = Field(
        default=0, ge=0,
        description="Total number of distinct client IPs evaluated",
    )
    observation_start: Optional[datetime] = Field(
        default=None,
        description="Earliest observed timestamp in analyzed batch (UTC)",
    )
    observation_end: Optional[datetime] = Field(
        default=None,
        description="Latest observed timestamp in analyzed batch (UTC)",
    )
    total_events_analyzed: int = Field(
        default=0, ge=0,
        description="Total number of traffic events analyzed",
    )
    summary: str = Field(
        ..., description="Human-readable summary of behavioral risk analysis"
    )

    model_config = ConfigDict(from_attributes=True)
