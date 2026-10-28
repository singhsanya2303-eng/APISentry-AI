"""
Brute-Force Detection Engine — Module 5, Step 1.

Deterministic, threshold-based detection of password/credential brute-forcing
against known authentication endpoints.

DESIGN PRINCIPLES:
  - client_ip is the PRIMARY attribution signal; actor_id is OPTIONAL context.
  - Only events targeting recognised authentication endpoints participate.
  - Only HTTP 401 responses count as authentication failures.
  - HTTP 403 (Forbidden) is NOT an authentication failure.
  - HTTP 2xx is tracked separately as a successful authentication response.
  - No ML, no external calls, no side effects, no credential inspection.
  - Fully deterministic: same input → same output.

SECURITY CONTRACT:
  - This module never inspects, stores, logs, or exposes:
      Authorization headers, Bearer tokens, cookies, API keys,
      passwords, secrets, or request bodies containing credentials.
  - actor_id must already be sanitised by the caller before being passed in.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from app.schemas.bruteforce import (
    BruteForceDetectionResult,
    BruteForceEvidence,
    BruteForceEvent,
    BruteForceVerdict,
)


# ---------------------------------------------------------------------------
# Authentication Endpoint Patterns
# ---------------------------------------------------------------------------

# Representative, narrow patterns only.
# These are exact-match or anchored-prefix matches — NOT substring searches.
# "auth" alone does NOT qualify; only specific login/signin paths do.
_DEFAULT_AUTH_PATH_PATTERNS: FrozenSet[str] = frozenset(
    [
        # Exact paths
        "/login",
        "/signin",
        # Prefixed variants commonly seen in REST APIs
        "/auth/login",
        "/auth/signin",
        "/api/v1/auth/login",
        "/api/v1/auth/signin",
        "/api/v2/auth/login",
        "/api/v2/auth/signin",
        "/api/auth/login",
        "/api/auth/signin",
        # Token/session endpoints that accept credentials
        "/auth/token",
        "/api/v1/auth/token",
        "/oauth/token",
        "/token",
        # Account login aliases
        "/account/login",
        "/accounts/login",
        "/user/login",
        "/users/login",
    ]
)


# ---------------------------------------------------------------------------
# Detector Configuration
# ---------------------------------------------------------------------------


class BruteForceDetectorConfig(BaseModel):
    """
    Centralised, adjustable configuration for the brute-force detector.

    All thresholds have sensible production defaults but can be overridden
    for testing or environment-specific tuning.
    """

    failure_threshold: int = Field(
        default=5,
        ge=1,
        description=(
            "Minimum number of 401 failures from a single client IP against "
            "the same auth endpoint within the time window to flag as a "
            "SUSPICIOUS_BRUTEFORCE_CANDIDATE."
        ),
    )
    time_window_minutes: int = Field(
        default=15,
        ge=1,
        description=(
            "Rolling time window (minutes) within which failures are counted. "
            "Failures outside this window are excluded from grouping."
        ),
    )
    min_confidence: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score required for an evidence record to be reported.",
    )
    auth_path_patterns: FrozenSet[str] = Field(
        default=_DEFAULT_AUTH_PATH_PATTERNS,
        description=(
            "Set of exact lower-cased path strings recognised as authentication endpoints. "
            "Do NOT add broad patterns such as every path containing 'auth'."
        ),
    )

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalise_path(path: str) -> str:
    """Lowercase and strip trailing slash for consistent matching."""
    return path.strip().rstrip("/").lower()


def _is_auth_endpoint(path: str, patterns: FrozenSet[str]) -> bool:
    """
    Return True only if path (after normalisation) is an exact member of the
    configured authentication endpoint set.

    Deliberate design choice: we do NOT do substring / contains-style matching.
    A path like /api/v1/users/auth-status is NOT a login endpoint.
    """
    return _normalise_path(path) in patterns


def _is_auth_failure(status_code: int) -> bool:
    """HTTP 401 = authentication failure. 403 is NOT an auth failure."""
    return status_code == 401


def _is_successful_auth(status_code: int) -> bool:
    """HTTP 2xx = successful authentication response."""
    return 200 <= status_code < 300


def _is_forbidden(status_code: int) -> bool:
    """HTTP 403 = authorization denied. Tracked separately, not a failure."""
    return status_code == 403


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class BruteForceDetector:
    """
    Deterministic Brute-Force Detection Engine.

    Analyses a sequence of BruteForceEvent records for repeated authentication
    failures from the same client IP against the same authentication endpoint
    within a configurable time window.

    Usage::

        detector = BruteForceDetector()
        result = detector.analyze_events(events)

    The detector is stateless; each call to ``analyze_events`` is independent.
    """

    def __init__(self, config: Optional[BruteForceDetectorConfig] = None) -> None:
        self.config = config or BruteForceDetectorConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_events(
        self, events: List[BruteForceEvent]
    ) -> BruteForceDetectionResult:
        """
        Analyse a list of BruteForceEvent records and return a detection result.

        Steps:
          1. Discard events without a usable client_ip.
          2. Discard events whose path is not a recognised auth endpoint.
          3. Apply the time-window filter (relative to the latest timestamp).
          4. Group by (client_ip, auth_endpoint).
          5. For each group count: failures (401), successes (2xx), forbidden (403).
          6. Emit evidence for groups at or above the failure threshold.
          7. Derive overall verdict.
        """
        if not events:
            return BruteForceDetectionResult(
                verdict=BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
                analyzed_event_count=0,
                failed_attempt_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary="No traffic events provided for brute-force analysis.",
            )

        total_count = len(events)
        patterns = self.config.auth_path_patterns

        # ---- Step 1: filter missing client_ip --------------------------------
        missing_ip_count = sum(1 for e in events if not e.client_ip)
        auth_candidate_events = [e for e in events if e.client_ip]

        # ---- Step 2: filter to auth endpoints only ---------------------------
        auth_candidate_events = [
            e for e in auth_candidate_events if _is_auth_endpoint(e.path, patterns)
        ]

        if not auth_candidate_events:
            # Could be all missing IPs, no auth-endpoint events, or both
            if missing_ip_count == total_count:
                return BruteForceDetectionResult(
                    verdict=BruteForceVerdict.INSUFFICIENT_EVIDENCE,
                    analyzed_event_count=total_count,
                    failed_attempt_count=0,
                    distinct_client_count=0,
                    distinct_actor_count=0,
                    evidences=[],
                    summary=(
                        f"Insufficient evidence: {missing_ip_count} event(s) lacked "
                        "a client IP address required for attribution."
                    ),
                )
            return BruteForceDetectionResult(
                verdict=BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
                analyzed_event_count=total_count,
                failed_attempt_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary="No events targeting recognised authentication endpoints were found.",
            )

        # ---- Step 3: time-window filter (relative to latest timestamp) --------
        latest_ts = max(e.timestamp for e in auth_candidate_events)
        # Ensure latest_ts is timezone-aware
        if latest_ts.tzinfo is None:
            latest_ts = latest_ts.replace(tzinfo=timezone.utc)
        window_start = latest_ts - timedelta(minutes=self.config.time_window_minutes)

        windowed_events: List[BruteForceEvent] = []
        for e in auth_candidate_events:
            ts = e.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= window_start:
                windowed_events.append(e)

        if not windowed_events:
            return BruteForceDetectionResult(
                verdict=BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
                analyzed_event_count=total_count,
                failed_attempt_count=0,
                distinct_client_count=0,
                distinct_actor_count=0,
                evidences=[],
                summary="All auth-endpoint events fell outside the configured time window.",
            )

        # ---- Step 4: group by (client_ip, auth_endpoint) ---------------------
        # Key: (client_ip_lower, normalised_path)
        GroupKey = Tuple[str, str]
        groups: Dict[GroupKey, List[BruteForceEvent]] = {}

        for e in windowed_events:
            key: GroupKey = (e.client_ip.strip(), _normalise_path(e.path))
            groups.setdefault(key, []).append(e)

        # ---- Step 5 & 6: count per group, build evidence ---------------------
        evidences: List[BruteForceEvidence] = []
        total_failures = 0
        distinct_clients: Set[str] = set()
        distinct_actors: Set[str] = set()

        for (client_ip, auth_endpoint), group in groups.items():
            sorted_group = sorted(
                group,
                key=lambda e: (
                    e.timestamp
                    if e.timestamp.tzinfo is not None
                    else e.timestamp.replace(tzinfo=timezone.utc)
                ),
            )

            failures = [e for e in sorted_group if _is_auth_failure(e.status_code)]
            successes = [e for e in sorted_group if _is_successful_auth(e.status_code)]
            forbiddens = [e for e in sorted_group if _is_forbidden(e.status_code)]

            fail_count = len(failures)
            succ_count = len(successes)
            forb_count = len(forbiddens)

            total_failures += fail_count

            if fail_count == 0:
                # No failures in this group — no evidence to report
                continue

            distinct_clients.add(client_ip)

            # Collect actor_id(s) present in the group — preserve as context
            actor_ids_in_group: List[Optional[str]] = [
                e.actor_id for e in sorted_group if e.actor_id
            ]
            # Use the most common actor_id in the group, or None if absent
            representative_actor: Optional[str] = None
            if actor_ids_in_group:
                representative_actor = max(
                    set(actor_ids_in_group), key=actor_ids_in_group.count
                )
                distinct_actors.add(representative_actor)

            # ---- Confidence scoring (deterministic) -------------------------
            # Base score starts at min_confidence; scaled by how far above threshold
            if fail_count >= self.config.failure_threshold:
                ratio = min(fail_count / max(self.config.failure_threshold, 1), 3.0)
                # Normalise: at threshold → ~0.75; 3× threshold → ~0.95
                conf = self.config.min_confidence + (1.0 - self.config.min_confidence) * (
                    (ratio - 1.0) / 2.0
                )
                conf = round(min(0.97, max(self.config.min_confidence, conf)), 2)
            else:
                # Below threshold — still build partial evidence but do not report
                conf = round(
                    self.config.min_confidence
                    * (fail_count / self.config.failure_threshold),
                    2,
                )

            # ---- Explanation (deterministic, no credentials) ----------------
            window_desc = f"{self.config.time_window_minutes} minute(s)"
            explanation = (
                f"Client {client_ip} generated {fail_count} failed authentication "
                f"attempt(s) against {auth_endpoint} within {window_desc}."
            )
            if succ_count:
                explanation += (
                    f" Additionally, {succ_count} successful authentication "
                    f"response(s) (2xx) were observed."
                )
            if forb_count:
                explanation += (
                    f" {forb_count} forbidden response(s) (403) were observed "
                    f"(not counted as authentication failures)."
                )

            # ---- Only emit evidence at or above threshold -------------------
            if fail_count < self.config.failure_threshold:
                continue

            ev = BruteForceEvidence(
                client_ip=client_ip,
                actor_id=representative_actor,
                auth_endpoint=auth_endpoint,
                failed_attempt_count=fail_count,
                successful_attempt_count=succ_count,
                forbidden_count=forb_count,
                timestamps=[
                    (
                        e.timestamp
                        if e.timestamp.tzinfo is not None
                        else e.timestamp.replace(tzinfo=timezone.utc)
                    )
                    for e in sorted_group
                ],
                request_ids=[e.request_id for e in sorted_group],
                status_codes=[e.status_code for e in sorted_group],
                confidence_score=conf,
                explanation=explanation,
            )
            evidences.append(ev)

        # ---- Step 7: overall verdict ----------------------------------------
        if evidences:
            verdict = BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
            summary = (
                f"Suspicious brute-force candidate detected: "
                f"{len(evidences)} (client_ip, auth_endpoint) group(s) exceeded "
                f"the failure threshold of {self.config.failure_threshold} "
                f"within {self.config.time_window_minutes} minute(s)."
            )
        elif missing_ip_count > 0 and not windowed_events:
            verdict = BruteForceVerdict.INSUFFICIENT_EVIDENCE
            summary = (
                f"Insufficient evidence: {missing_ip_count} event(s) lacked "
                "a client IP address required for attribution."
            )
        else:
            verdict = BruteForceVerdict.NO_BRUTEFORCE_DETECTED
            summary = (
                "No brute-force pattern detected. "
                f"Total authentication failures observed: {total_failures}."
            )

        return BruteForceDetectionResult(
            verdict=verdict,
            analyzed_event_count=total_count,
            failed_attempt_count=total_failures,
            distinct_client_count=len(distinct_clients),
            distinct_actor_count=len(distinct_actors),
            evidences=evidences,
            summary=summary,
        )
