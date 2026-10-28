"""
Rate Anomaly & Abuse Detection Engine — Module 6, Step 1.

Deterministic, threshold-based detection of abnormal API request velocity/volume.

DESIGN PRINCIPLES:
  - client_ip is the PRIMARY attribution signal; actor_id is OPTIONAL context.
  - Rate anomaly evaluates request throughput (volume over time), NOT authentication status.
  - All valid HTTP status codes (2xx, 3xx, 4xx, 5xx) participate in request rate.
  - Supports both endpoint-scoped and client-wide analysis.
  - No ML, no external calls, no database access, no credential inspection.
  - Fully deterministic: same input + same config -> same output.

SECURITY CONTRACT:
  - Never inspects, stores, logs, or exposes credentials, tokens, cookies,
    passwords, secrets, or request bodies.
  - Explanations use safe, deterministic string formatting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from app.schemas.rate_anomaly import (
    RateAnomalyDetectionResult,
    RateAnomalyEvidence,
    RateAnomalyEvent,
    RateAnomalyVerdict,
)


# ---------------------------------------------------------------------------
# Detector Configuration
# ---------------------------------------------------------------------------

class RateAnomalyDetectorConfig(BaseModel):
    """
    Configurable detection thresholds and scope for rate-anomaly analysis.
    """

    request_threshold: int = Field(
        default=50,
        ge=2,
        description="Minimum number of requests in the time window to flag a rate anomaly candidate"
    )
    time_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Rolling analysis time window duration in seconds"
    )
    min_confidence: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for an evidence record"
    )
    scope: str = Field(
        default="endpoint",
        description="Analysis grouping scope: 'endpoint' (client_ip, path) or 'client_wide' (client_ip only)"
    )


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _normalise_path(path: str) -> str:
    """Normalize URI path for consistent endpoint-level grouping."""
    if not path:
        return "/"
    cleaned = path.strip()
    if cleaned != "/":
        cleaned = cleaned.rstrip("/")
    return cleaned.lower()


def _ensure_utc(ts: Optional[datetime]) -> datetime:
    """Ensure datetime object is timezone-aware in UTC."""
    if ts is None:
        return datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Detector Engine
# ---------------------------------------------------------------------------

class RateAnomalyDetector:
    """
    Deterministic Rate Anomaly & Abuse Detection Engine.

    Analyzes sequences of RateAnomalyEvent records to identify clients generating
    unusually high request rates within a configurable temporal window.
    """

    def __init__(self, config: Optional[RateAnomalyDetectorConfig] = None) -> None:
        self.config = config or RateAnomalyDetectorConfig()

    def analyze_events(
        self, events: List[RateAnomalyEvent]
    ) -> RateAnomalyDetectionResult:
        """
        Analyze a list of RateAnomalyEvent records and return a detection result.

        Steps:
          1. Check for empty input.
          2. Filter events with valid client_ip attribution.
          3. Apply rolling time window (relative to latest event timestamp).
          4. Group events by configured scope ('endpoint' or 'client_wide').
          5. Calculate request volume, rates (req/sec, req/min), and confidence.
          6. Generate evidence for groups exceeding the request threshold.
          7. Assemble and return RateAnomalyDetectionResult.
        """
        if not events:
            return RateAnomalyDetectionResult(
                verdict=RateAnomalyVerdict.NO_ANOMALY,
                analyzed_event_count=0,
                anomalous_request_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary="No traffic events provided for rate anomaly analysis."
            )

        total_count = len(events)

        # Step 1: Filter events by client_ip attribution
        missing_ip_count = sum(1 for e in events if not e.client_ip or not e.client_ip.strip())
        valid_events = [e for e in events if e.client_ip and e.client_ip.strip()]

        if not valid_events:
            return RateAnomalyDetectionResult(
                verdict=RateAnomalyVerdict.INSUFFICIENT_EVIDENCE,
                analyzed_event_count=total_count,
                anomalous_request_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary=f"Insufficient evidence: {missing_ip_count} event(s) lacked a client IP address required for attribution."
            )

        # Step 2: Time window filtering (relative to latest valid event timestamp)
        latest_ts = max(_ensure_utc(e.timestamp) for e in valid_events)
        window_start = latest_ts - timedelta(seconds=self.config.time_window_seconds)

        windowed_events = [
            e for e in valid_events
            if _ensure_utc(e.timestamp) >= window_start
        ]

        if not windowed_events:
            return RateAnomalyDetectionResult(
                verdict=RateAnomalyVerdict.NO_ANOMALY,
                analyzed_event_count=total_count,
                anomalous_request_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary="All events fell outside the configured time window."
            )

        # Step 3: Group events by scope
        # Key: (client_ip, analyzed_endpoint)
        is_client_wide = (self.config.scope.lower() == "client_wide")
        groups: Dict[Tuple[str, str], List[RateAnomalyEvent]] = {}

        for e in windowed_events:
            client_ip = e.client_ip.strip()
            endpoint = "CLIENT_WIDE" if is_client_wide else _normalise_path(e.path)
            key = (client_ip, endpoint)
            groups.setdefault(key, []).append(e)

        # Step 4: Evaluate rate per group
        evidences: List[RateAnomalyEvidence] = []
        anomalous_requests_total = 0
        distinct_clients: Set[str] = set()
        distinct_actors: Set[str] = set()

        window_duration_seconds = max(1.0, float(self.config.time_window_seconds))

        for (client_ip, endpoint), group in groups.items():
            sorted_group = sorted(group, key=lambda e: _ensure_utc(e.timestamp))
            count = len(sorted_group)

            if count < self.config.request_threshold:
                continue

            distinct_clients.add(client_ip)
            anomalous_requests_total += count

            # Calculate throughput metrics
            rps = round(count / window_duration_seconds, 3)
            rpm = round(rps * 60.0, 2)

            # Preserved actor context if present
            actors = [e.actor_id for e in sorted_group if e.actor_id]
            rep_actor = max(set(actors), key=actors.count) if actors else None
            if rep_actor:
                distinct_actors.add(rep_actor)

            # Deterministic confidence scaling
            ratio = min(count / max(self.config.request_threshold, 1), 3.0)
            conf = self.config.min_confidence + (1.0 - self.config.min_confidence) * ((ratio - 1.0) / 2.0)
            conf = round(min(0.98, max(self.config.min_confidence, conf)), 2)

            # Build explanation
            if is_client_wide:
                explanation = (
                    f"Client {client_ip} generated {count} requests across all endpoints "
                    f"within {self.config.time_window_seconds} second(s) ({rps} req/sec), "
                    f"exceeding rate threshold of {self.config.request_threshold} requests."
                )
            else:
                explanation = (
                    f"Client {client_ip} generated {count} requests against {endpoint} "
                    f"within {self.config.time_window_seconds} second(s) ({rps} req/sec), "
                    f"exceeding rate threshold of {self.config.request_threshold} requests."
                )

            ev = RateAnomalyEvidence(
                client_ip=client_ip,
                actor_id=rep_actor,
                analyzed_endpoint=endpoint,
                request_count=count,
                time_window_seconds=window_duration_seconds,
                requests_per_second=rps,
                requests_per_minute=rpm,
                timestamps=[_ensure_utc(e.timestamp) for e in sorted_group],
                request_ids=[e.request_id for e in sorted_group],
                status_codes=[e.status_code for e in sorted_group],
                confidence_score=conf,
                explanation=explanation
            )
            evidences.append(ev)

        # Step 5: Determine overall verdict
        if evidences:
            verdict = RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
            summary = (
                f"Suspicious rate anomaly detected: {len(evidences)} client/endpoint group(s) "
                f"exceeded the rate threshold of {self.config.request_threshold} requests "
                f"within {self.config.time_window_seconds} second(s)."
            )
        else:
            verdict = RateAnomalyVerdict.NO_ANOMALY
            summary = f"No rate anomalies detected across {total_count} analyzed event(s)."

        return RateAnomalyDetectionResult(
            verdict=verdict,
            analyzed_event_count=total_count,
            anomalous_request_count=anomalous_requests_total,
            distinct_client_count=len(distinct_clients),
            distinct_actor_count=len(distinct_actors),
            evidences=evidences,
            summary=summary
        )
