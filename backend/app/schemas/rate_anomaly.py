"""
Rate Anomaly & Abuse Detection Schemas — Module 6, Step 1.

All schemas are derived exclusively from fields available in APITrafficLog
and safe external context (e.g. non-sensitive X-User-ID headers).

SECURITY CONTRACT:
  - Authorization headers, Bearer tokens, cookies, API keys, passwords,
    and any credential-bearing data are NEVER stored, logged, or exposed.
  - actor_id is OPTIONAL supporting context; client_ip is the primary
    attribution signal.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class RateAnomalyVerdict(str, Enum):
    """Top-level verdict for a rate-anomaly detection analysis run."""

    NO_ANOMALY = "no_anomaly"
    """Analyzed events do not exceed the rate threshold."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    """Events were present but lacked sufficient attribution (e.g. missing client_ip) to conclude."""

    SUSPICIOUS_RATE_ANOMALY = "suspicious_rate_anomaly"
    """At or above the rate threshold; warrants review. NOT a confirmed attack."""


# ---------------------------------------------------------------------------
# Per-Event Input
# ---------------------------------------------------------------------------

class RateAnomalyEvent(BaseModel):
    """
    A single API traffic event submitted for rate anomaly analysis.

    Fields map 1-to-1 to APITrafficLog columns plus optional safe context.
    Credential-bearing fields are strictly excluded.
    """

    request_id: str = Field(..., description="Unique correlation ID for request tracing")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC-aware timestamp of the API request"
    )
    method: str = Field(..., description="HTTP method (e.g. GET, POST)")
    path: str = Field(..., description="Request URI path")

    # Primary attribution signal — optional to allow safe handling of missing IPs
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address. Primary attribution signal for rate anomaly detection."
    )

    # Optional supporting context — never derived from credentials
    actor_id: Optional[str] = Field(
        default=None,
        description=(
            "Non-sensitive actor/user identity when safely available. "
            "NEVER populated from Authorization, Bearer tokens, cookies, or API keys."
        )
    )

    status_code: int = Field(..., description="HTTP response status code")

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Optional per-event confidence weight (default 1.0)"
    )

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Per-Group Evidence
# ---------------------------------------------------------------------------

class RateAnomalyEvidence(BaseModel):
    """
    Structured evidence for a single suspicious rate-anomaly pattern.
    Grouped by (client_ip, analyzed_endpoint) or client_ip alone.
    """

    client_ip: str = Field(..., description="Client IP address generating the anomalous request volume")
    actor_id: Optional[str] = Field(
        default=None,
        description="Non-sensitive actor identity observed in this group, if available"
    )
    analyzed_endpoint: str = Field(..., description="Target endpoint or scope analyzed (e.g. '/api/v1/orders' or 'CLIENT_WIDE')")

    request_count: int = Field(
        ...,
        ge=0,
        description="Total number of requests observed within the time window"
    )
    time_window_seconds: float = Field(
        ...,
        gt=0,
        description="Analysis time window duration in seconds"
    )
    requests_per_second: float = Field(
        ...,
        ge=0.0,
        description="Calculated request rate in requests per second"
    )
    requests_per_minute: float = Field(
        ...,
        ge=0.0,
        description="Calculated request rate in requests per minute"
    )

    timestamps: List[datetime] = Field(
        default_factory=list,
        description="Ordered UTC timestamps of contributing requests"
    )
    request_ids: List[str] = Field(
        default_factory=list,
        description="Request correlation IDs for contributing events"
    )
    status_codes: List[int] = Field(
        default_factory=list,
        description="Status codes for contributing events in timestamp order"
    )

    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Evidence confidence score (0.0 – 1.0)"
    )
    explanation: str = Field(
        ...,
        description="Deterministic, human-readable explanation. Never contains credentials."
    )

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Overall Detection Result
# ---------------------------------------------------------------------------

class RateAnomalyDetectionResult(BaseModel):
    """Overall output of a single rate-anomaly analysis run."""

    verdict: RateAnomalyVerdict = Field(..., description="Top-level detection verdict")

    analyzed_event_count: int = Field(
        ...,
        ge=0,
        description="Total number of RateAnomalyEvent records submitted for analysis"
    )
    anomalous_request_count: int = Field(
        default=0,
        ge=0,
        description="Total requests contributing to flagged rate anomaly evidences"
    )
    distinct_client_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct client IPs observed in candidate groups"
    )
    distinct_actor_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct actor_ids observed where available"
    )

    evidences: List[RateAnomalyEvidence] = Field(
        default_factory=list,
        description="List of evidence entries for identified rate anomalies"
    )
    summary: str = Field(
        ...,
        description="Human-readable summary of the overall analysis result"
    )

    model_config = ConfigDict(from_attributes=True)
