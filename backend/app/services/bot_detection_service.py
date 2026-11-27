"""
Bot Detection Service — Stage 1.

Deterministic, evidence-based bot classification over existing PostgreSQL traffic
logs. This service does not modify traffic, block requests, throttle clients, or
produce mitigation decisions.

PIPELINE:
    APITrafficLog
      -> existing traffic retrieval / pagination
      -> existing behavior event + feature extraction
      -> existing rate-anomaly and brute-force detectors
      -> existing User-Agent / request-pattern / historical analyzers
      -> independent deterministic bot score and classification

SCORING (independent from RiskScorer / behavioural risk):
  Default factor weights (points, clamped to 0-100 total):
    rate anomaly .................... 24
    brute-force candidate ........... 30
    raw auth-failure volume ......... 14
    User-Agent novelty ..............  6
    request-method novelty ..........  3
    request-path novelty ............  3
    historical-method deviation .....  3
    historical-path deviation .......  3
    endpoint diversity ..............  5
    resource diversity ..............  5
    stable repeated request pattern .  8
  Thresholds:
    minimum requests for classification ...... 5
    stable repetition minimum requests ....... 8
    stable repetition dominant-path share .... 0.8
    suspicious bot score threshold ........... 50
    rate detector defaults ................... 50 requests / 60 seconds / endpoint scope
    brute-force detector defaults ............ 5 failures / 15 minutes / auth endpoints
  All weights and thresholds are overridable via BotScoringConfig and detector configs.

CLASSIFICATION RULES:
  - Weak signals (rate, UA/method/path novelty, historical deviation, diversity,
    stable repetition, raw 401 volume) describe bot-like automation. They remain
    explainable score factors but never produce `automation_suspicious` on their own.
  - Grouped brute-force evidence is the only strong suspicious signal. By default,
    `brute_force_override_enabled=True` allows it to classify a client suspicious
    even below the score threshold; the trigger is emitted as `BRUTE_FORCE_OVERRIDE`.
  - With the override disabled, grouped brute-force evidence is still scored, but
    `automation_suspicious` requires bot_risk_score >= suspicious_score_threshold.
  - A shared IP may be split into per-actor groups; cross-actor evidence is not
    used to classify unrelated actors. An IP is never treated as an individual.

SECURITY CONTRACT:
  - No credentials, headers, cookies, tokens, passwords, or request bodies are read.
  - Only sanitized traffic metadata and opaque correlation references are emitted.
  - Every client-supplied request ID is replaced with a deterministic opaque UUID;
    the original value is never emitted anywhere in the response.
  - A User-Agent containing "bot" is never used as maliciousness evidence.
  - High volume alone raises automation risk but never implies malicious intent.
  - Missing or incomplete evidence never creates a high-risk classification.
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.detection.bruteforce_detector import BruteForceDetectorConfig
from app.detection.rate_anomaly_detector import RateAnomalyDetectorConfig
from app.schemas.behavior import BehaviorEvent, BehaviorFeatures
from app.schemas.bot_detection import (
    BehavioralRiskContext,
    BotAnalysisLimits,
    BotAnalysisResult,
    BotAnalysisSummary,
    BotClassification,
    BotDetectionResponse,
    BotEvidenceReference,
    BotReason,
    BotReasonCategory,
    BotReasonSeverity,
    BotScoreFactor,
)
from app.services.behavior_analysis_service import (
    analyze_traffic_for_behavior_risk,
    convert_traffic_log_to_behavior_event,
    extract_features_for_events,
)
from app.services.bruteforce_analysis_service import (
    analyze_events_directly as analyze_bruteforce_events,
    convert_traffic_log_to_bruteforce_event,
)
from app.services.historical_request_pattern_service import (
    analyze_historical_request_patterns,
    get_historical_window,
)
from app.services.rate_anomaly_analysis_service import (
    analyze_events_directly as analyze_rate_events,
    convert_traffic_log_to_rate_anomaly_event,
)
from app.services.request_pattern_anomaly_service import (
    analyze_http_method_frequency,
    analyze_request_path_frequency,
)
from app.services.traffic_service import (
    get_historical_traffic_logs,
    get_traffic_logs,
)
from app.services.user_agent_anomaly_service import analyze_user_agent_frequency

logger = logging.getLogger("apisentry.analysis.bot_detection")

MAX_RECORD_HARD_LIMIT = 5000


class BotScoringConfig(BaseModel):
    """Configurable weights and evidence thresholds for bot scoring."""

    rate_anomaly_weight: float = Field(default=24.0, ge=0.0, le=100.0)
    brute_force_weight: float = Field(default=30.0, ge=0.0, le=100.0)
    authentication_failure_weight: float = Field(default=14.0, ge=0.0, le=100.0)
    user_agent_novelty_weight: float = Field(default=6.0, ge=0.0, le=100.0)
    request_method_novelty_weight: float = Field(default=3.0, ge=0.0, le=100.0)
    request_path_novelty_weight: float = Field(default=3.0, ge=0.0, le=100.0)
    historical_method_novelty_weight: float = Field(default=3.0, ge=0.0, le=100.0)
    historical_path_novelty_weight: float = Field(default=3.0, ge=0.0, le=100.0)
    endpoint_diversity_weight: float = Field(default=5.0, ge=0.0, le=100.0)
    resource_diversity_weight: float = Field(default=5.0, ge=0.0, le=100.0)
    stable_repetition_weight: float = Field(default=8.0, ge=0.0, le=100.0)

    minimum_requests_for_classification: int = Field(default=5, ge=2, le=1000)
    authentication_failure_threshold: int = Field(default=5, ge=1, le=1000)
    stable_repetition_min_requests: int = Field(default=8, ge=2, le=1000)
    stable_repetition_min_share: float = Field(default=0.8, ge=0.5, le=1.0)
    high_endpoint_diversity_threshold: int = Field(default=12, ge=2, le=1000)
    high_resource_diversity_threshold: int = Field(default=15, ge=2, le=1000)
    suspicious_score_threshold: float = Field(default=50.0, ge=0.0, le=100.0)
    brute_force_override_enabled: bool = Field(
        default=True,
        description=(
            "When true, grouped brute-force evidence can classify a client "
            "automation_suspicious even when bot_risk_score is below the threshold."
        ),
    )
    max_evidence_references: int = Field(default=25, ge=1, le=200)


OPAQUE_REQUEST_ID_NAMESPACE = uuid.UUID("7f3a2b91-6c4d-4e8f-9a2b-5c8d1e7f0a34")
ClientGroupKey = Tuple[Optional[str], Optional[str]]


def _opaque_request_id(value: Any) -> str:
    """Return a deterministic opaque UUID5 reference for any request ID.

    The original value is never emitted. The same original produces the same
    reference within this scheme, preserving correlation across reasons and
    repeated analyses. The counter guard guarantees the generated reference is
    never identical even when the client supplied a UUID-shaped identifier.
    """
    raw = value if isinstance(value, str) else repr(value)
    counter = 0
    while True:
        material = f"apisentry.bot.request_id:{counter}:{raw}"
        reference = str(uuid.uuid5(OPAQUE_REQUEST_ID_NAMESPACE, material))
        if reference != raw:
            return reference
        counter += 1


def _opaque_request_ids(values: List[str]) -> List[str]:
    """Deterministically convert and de-duplicate request IDs into opaque UUIDs."""
    return _unique([_opaque_request_id(value) for value in values if value])


def _ensure_utc(timestamp: Optional[datetime]) -> datetime:
    if timestamp is None:
        return datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _unique(values: List[str]) -> List[str]:
    """Deterministic de-duplication preserving first-seen order."""
    seen = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _scaled(weight: float, count: int, full_at: int) -> float:
    """Scale a factor linearly to its configured maximum."""
    if weight <= 0 or count <= 0:
        return 0.0
    ratio = min(float(count) / float(max(1, full_at)), 1.0)
    return round(weight * ratio, 1)


def _client_group_key(event: BehaviorEvent) -> ClientGroupKey:
    """Group by client IP and, when available, a safe actor identity.

    A client IP is a network attribution, not an individual identity. Splitting
    only happens when more than one actor key is present for the same IP.
    """
    client_ip = (
        event.client_ip.strip()
        if isinstance(event.client_ip, str) and event.client_ip.strip()
        else None
    )
    actor_id = (
        event.actor_id.strip()
        if isinstance(event.actor_id, str) and event.actor_id.strip()
        else None
    )
    return (client_ip, actor_id)


def _filter_detector_evidences(
    evidences: List[Any],
    group_key: ClientGroupKey,
    shared_ips: Set[str],
    group_by_request_id: Dict[str, ClientGroupKey],
) -> Tuple[List[Any], bool]:
    """Attribute IP-scoped detector evidence to one actor group conservatively.

    On a shared IP, evidence is used only when every attributable request belongs
    to this exact group. Cross-actor or unattributable evidence is dropped and
    reported as ambiguity instead of contaminating unrelated actors.
    """
    selected: List[Any] = []
    ambiguous = False

    for evidence in evidences:
        raw_ip = getattr(evidence, "client_ip", None)
        evidence_ip = (
            raw_ip.strip() if isinstance(raw_ip, str) and raw_ip.strip() else None
        )
        if evidence_ip != group_key[0]:
            continue
        if evidence_ip not in shared_ips:
            selected.append(evidence)
            continue

        contributing_keys = {
            key
            for key in (
                group_by_request_id.get(request_id)
                for request_id in (getattr(evidence, "request_ids", []) or [])
            )
            if key is not None
        }
        if not contributing_keys:
            ambiguous = True
            continue
        if contributing_keys == {group_key}:
            selected.append(evidence)
        else:
            ambiguous = True

    return selected, ambiguous


def _signals_for_group(
    signal: Dict[str, Any],
    group_key: ClientGroupKey,
    group_by_request_id: Dict[str, ClientGroupKey],
    keys: Tuple[str, ...],
) -> Dict[str, List[str]]:
    """Keep only request IDs belonging to one actor group."""
    result: Dict[str, List[str]] = {key: [] for key in keys}
    for key in keys:
        for request_id in signal.get(key, []) or []:
            if group_by_request_id.get(request_id) == group_key:
                result[key].append(request_id)
    return result


def _fetch_traffic_records(
    *,
    method: Optional[str],
    path: Optional[str],
    status_code: Optional[int],
    client_ip: Optional[str],
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    page: int,
    page_size: int,
    max_records: int,
    db: Optional[Session],
) -> Tuple[List[Any], bool]:
    """Retrieve traffic using existing pagination conventions with a hard bound."""
    safe_page = max(1, page)
    safe_page_size = min(max(1, page_size), 500)
    safe_max_records = min(max(1, max_records), MAX_RECORD_HARD_LIMIT)

    common = dict(
        method=method,
        path=path,
        status_code=status_code,
        client_ip=client_ip,
        start_time=start_time,
        end_time=end_time,
        db=db,
    )

    if safe_page > 1:
        return get_traffic_logs(page=safe_page, page_size=safe_page_size, **common), False

    records: List[Any] = []
    current_page = 1
    # Fixed for every database fetch: get_traffic_logs() derives its SQL OFFSET
    # from (page - 1) * page_size, so changing page_size between calls would
    # duplicate and skip records.
    fetch_page_size = min(500, max(50, safe_page_size))
    truncated = False

    while len(records) < safe_max_records:
        batch = get_traffic_logs(
            page=current_page, page_size=fetch_page_size, **common
        )
        if not batch:
            break

        remaining = safe_max_records - len(records)
        records.extend(batch[:remaining])

        if len(batch) > remaining:
            truncated = True
            break
        if len(batch) < fetch_page_size:
            break
        if len(records) >= safe_max_records:
            # Exact multiple: probe the next page with the same page size so
            # truncated reflects unanalyzed matching records, not just a count.
            following = get_traffic_logs(
                page=current_page + 1, page_size=fetch_page_size, **common
            )
            truncated = bool(following)
            break
        current_page += 1

    return records, truncated


def _collect_historical_findings(
    *,
    events: List[BehaviorEvent],
    client_ips: List[str],
    end_time: Optional[datetime],
    db: Optional[Session],
) -> List[Dict[str, Any]]:
    """Retrieve historical traffic and reuse the existing baseline analyzer."""
    if not events or not client_ips or db is None:
        return []

    try:
        anchor = _ensure_utc(end_time) if end_time else max(
            _ensure_utc(event.timestamp) for event in events
        )
        history_start, history_end = get_historical_window(anchor)
        historical_logs = get_historical_traffic_logs(
            client_ips=client_ips,
            start_time=history_start,
            end_time=history_end,
            db=db,
        )
        return analyze_historical_request_patterns(
            current_events=events,
            historical_events=historical_logs,
        )
    except Exception as exc:
        logger.warning("Bot historical-pattern review skipped: %s", exc)
        return []


def _representative_actor(events: List[BehaviorEvent]) -> Optional[str]:
    actors = [event.actor_id for event in events if event.actor_id]
    if not actors:
        return None
    return sorted(set(actors), key=lambda value: (-actors.count(value), value))[0]


def _score_client(
    *,
    client_ip: Optional[str],
    actor_key: Optional[str],
    events: List[BehaviorEvent],
    features: Optional[BehaviorFeatures],
    rate_evidences: List[Any],
    brute_evidences: List[Any],
    ua_signal: Dict[str, Any],
    pattern_signal: Dict[str, Any],
    historical_signal: Dict[str, Any],
    config: BotScoringConfig,
    timestamps_by_request: Dict[str, datetime],
    shared_ip_attribution: bool = False,
    cross_actor_evidence_dropped: bool = False,
) -> BotAnalysisResult:
    """Produce one deterministic bot assessment for an attributed client group."""
    request_count = len(events)
    reasons: List[BotReason] = []
    factors: List[BotScoreFactor] = []
    automation_indicators: List[str] = []
    strong_suspicious_signal = False
    max_refs = config.max_evidence_references
    opaque_timestamps = {
        _opaque_request_id(request_id): timestamp
        for request_id, timestamp in timestamps_by_request.items()
    }

    timestamps = [_ensure_utc(event.timestamp) for event in events]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None
    observation_seconds = round(
        max(0.0, (last_seen - first_seen).total_seconds()) if first_seen and last_seen else 0.0,
        2,
    )

    # 1. Existing rate-anomaly detector evidence.
    if rate_evidences:
        contributing_requests = sum(
            int(getattr(evidence, "request_count", 0)) for evidence in rate_evidences
        )
        request_ids = _unique([
            request_id
            for evidence in rate_evidences
            for request_id in getattr(evidence, "request_ids", [])
        ])
        contribution = _scaled(
            config.rate_anomaly_weight, contributing_requests, 50
        )
        reasons.append(
            BotReason(
                code="HIGH_REQUEST_VELOCITY",
                category=BotReasonCategory.RATE_ANOMALY,
                description=(
                    f"{contributing_requests} request(s) contributed to "
                    f"{len(rate_evidences)} rate-anomaly group(s) exceeding the "
                    "configured velocity baseline. This is automation-like velocity, "
                    "not proof of malicious intent."
                ),
                severity=BotReasonSeverity.HIGH,
                evidence_count=contributing_requests,
                score_contribution=contribution,
                request_ids=_opaque_request_ids(request_ids)[:max_refs],
                details={"evidence_group_count": len(rate_evidences)},
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="rate_anomaly",
                contribution=contribution,
                evidence_count=contributing_requests,
                description="Existing rate-anomaly detector evidence for this client.",
            )
        )
        automation_indicators.append("HIGH_REQUEST_VELOCITY")

    # 2. Existing brute-force detector evidence; raw 401 volume only if no
    #    brute-force grouping was produced (avoids double counting).
    auth_failure_count = features.authentication_failure_count if features else sum(
        1 for event in events if event.status_code == 401
    )
    if brute_evidences:
        failed_attempts = sum(
            int(getattr(evidence, "failed_attempt_count", 0))
            for evidence in brute_evidences
        )
        request_ids = _unique([
            request_id
            for evidence in brute_evidences
            for request_id in getattr(evidence, "request_ids", [])
        ])
        contribution = _scaled(config.brute_force_weight, failed_attempts, 5)
        reasons.append(
            BotReason(
                code="REPEATED_AUTHENTICATION_FAILURES",
                category=BotReasonCategory.AUTHENTICATION,
                description=(
                    f"The existing brute-force detector grouped {failed_attempts} "
                    f"HTTP 401 response(s) into {len(brute_evidences)} candidate "
                    "pattern(s). This warrants review and is not a confirmed compromise."
                ),
                severity=BotReasonSeverity.HIGH,
                evidence_count=failed_attempts,
                score_contribution=contribution,
                request_ids=_opaque_request_ids(request_ids)[:max_refs],
                details={"evidence_group_count": len(brute_evidences)},
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="brute_force_candidate",
                contribution=contribution,
                evidence_count=failed_attempts,
                description="Existing brute-force detector evidence for this client.",
            )
        )
        strong_suspicious_signal = True
    elif auth_failure_count >= config.authentication_failure_threshold:
        request_ids = _unique([
            event.request_id for event in events if event.status_code == 401
        ])
        contribution = _scaled(
            config.authentication_failure_weight, auth_failure_count, 10
        )
        reasons.append(
            BotReason(
                code="AUTHENTICATION_FAILURE_VOLUME",
                category=BotReasonCategory.AUTHENTICATION,
                description=(
                    f"{auth_failure_count} HTTP 401 response(s) were observed without "
                    "a grouped brute-force candidate. This is an authentication review "
                    "signal, not proof of automation or attack."
                ),
                severity=BotReasonSeverity.MEDIUM,
                evidence_count=auth_failure_count,
                score_contribution=contribution,
                request_ids=_opaque_request_ids(request_ids)[:max_refs],
                details={"threshold": config.authentication_failure_threshold},
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="authentication_failures",
                contribution=contribution,
                evidence_count=auth_failure_count,
                description="Repeated HTTP 401 responses for this client.",
            )
        )

    # 3. User-Agent novelty is a supporting signal only. Raw User-Agent values
    #    are never emitted.
    ua_request_ids = _unique(list(ua_signal.get("request_ids", [])))
    ua_values = int(ua_signal.get("value_count", 0))
    if ua_request_ids:
        contribution = _scaled(config.user_agent_novelty_weight, max(1, ua_values), 3)
        reasons.append(
            BotReason(
                code="USER_AGENT_NOVELTY",
                category=BotReasonCategory.USER_AGENT,
                description=(
                    f"{len(ua_request_ids)} request(s) used a User-Agent differing "
                    "from this client's most frequent value. This is a supporting "
                    "review signal and is not proof of malicious automation."
                ),
                severity=BotReasonSeverity.LOW,
                evidence_count=len(ua_request_ids),
                score_contribution=contribution,
                request_ids=_opaque_request_ids(ua_request_ids)[:max_refs],
                details={"novel_value_count": ua_values},
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="user_agent_novelty",
                contribution=contribution,
                evidence_count=len(ua_request_ids),
                description="User-Agent values differing from the client baseline.",
            )
        )

    # 4. Request-pattern novelty from existing method/path frequency analyzers.
    method_ids = _unique(list(pattern_signal.get("method_ids", [])))
    if method_ids:
        contribution = _scaled(
            config.request_method_novelty_weight, len(method_ids), 4
        )
        reasons.append(
            BotReason(
                code="REQUEST_METHOD_PATTERN_VARIATION",
                category=BotReasonCategory.REQUEST_PATTERN,
                description=(
                    f"{len(method_ids)} request(s) used an HTTP method differing "
                    "from this client's most frequent method in the analyzed batch."
                ),
                severity=BotReasonSeverity.LOW,
                evidence_count=len(method_ids),
                score_contribution=contribution,
                request_ids=_opaque_request_ids(method_ids)[:max_refs],
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="request_method_novelty",
                contribution=contribution,
                evidence_count=len(method_ids),
                description="HTTP-method variation within the analyzed batch.",
            )
        )

    path_ids = _unique(list(pattern_signal.get("path_ids", [])))
    if path_ids:
        contribution = _scaled(config.request_path_novelty_weight, len(path_ids), 4)
        reasons.append(
            BotReason(
                code="REQUEST_PATH_PATTERN_VARIATION",
                category=BotReasonCategory.REQUEST_PATTERN,
                description=(
                    f"{len(path_ids)} request(s) used a path differing from this "
                    "client's most frequent path in the analyzed batch."
                ),
                severity=BotReasonSeverity.LOW,
                evidence_count=len(path_ids),
                score_contribution=contribution,
                request_ids=_opaque_request_ids(path_ids)[:max_refs],
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="request_path_novelty",
                contribution=contribution,
                evidence_count=len(path_ids),
                description="Request-path variation within the analyzed batch.",
            )
        )

    # 5. Historical deviations from existing baseline analyzer.
    historical_method_ids = _unique(list(historical_signal.get("method_ids", [])))
    if historical_method_ids:
        contribution = _scaled(
            config.historical_method_novelty_weight, len(historical_method_ids), 4
        )
        reasons.append(
            BotReason(
                code="HISTORICAL_METHOD_DEVIATION",
                category=BotReasonCategory.HISTORICAL_PATTERN,
                description=(
                    f"{len(historical_method_ids)} request(s) used an HTTP method "
                    "not present in this client's sufficient historical baseline."
                ),
                severity=BotReasonSeverity.LOW,
                evidence_count=len(historical_method_ids),
                score_contribution=contribution,
                request_ids=_opaque_request_ids(historical_method_ids)[:max_refs],
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="historical_method_novelty",
                contribution=contribution,
                evidence_count=len(historical_method_ids),
                description="HTTP methods absent from the client historical baseline.",
            )
        )

    historical_path_ids = _unique(list(historical_signal.get("path_ids", [])))
    if historical_path_ids:
        contribution = _scaled(
            config.historical_path_novelty_weight, len(historical_path_ids), 4
        )
        reasons.append(
            BotReason(
                code="HISTORICAL_PATH_DEVIATION",
                category=BotReasonCategory.HISTORICAL_PATTERN,
                description=(
                    f"{len(historical_path_ids)} request(s) used a path not present "
                    "in this client's sufficient historical baseline."
                ),
                severity=BotReasonSeverity.LOW,
                evidence_count=len(historical_path_ids),
                score_contribution=contribution,
                request_ids=_opaque_request_ids(historical_path_ids)[:max_refs],
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="historical_path_novelty",
                contribution=contribution,
                evidence_count=len(historical_path_ids),
                description="Paths absent from the client historical baseline.",
            )
        )

    # 6. Endpoint/resource diversity from existing behavior features.
    if features:
        if features.unique_endpoints >= config.high_endpoint_diversity_threshold:
            contribution = _scaled(
                config.endpoint_diversity_weight,
                features.unique_endpoints - config.high_endpoint_diversity_threshold + 1,
                20,
            )
            reasons.append(
                BotReason(
                    code="HIGH_ENDPOINT_DIVERSITY",
                    category=BotReasonCategory.ENDPOINT_DIVERSITY,
                    description=(
                        f"{features.unique_endpoints} distinct normalized endpoints "
                        "were accessed by this client. Diversity alone is not malicious."
                    ),
                    severity=BotReasonSeverity.LOW,
                    evidence_count=features.unique_endpoints,
                    score_contribution=contribution,
                    details={"threshold": config.high_endpoint_diversity_threshold},
                )
            )
            factors.append(
                BotScoreFactor(
                    factor_name="endpoint_diversity",
                    contribution=contribution,
                    evidence_count=features.unique_endpoints,
                    description="Elevated normalized endpoint diversity.",
                )
            )

        if features.unique_resource_ids >= config.high_resource_diversity_threshold:
            contribution = _scaled(
                config.resource_diversity_weight,
                features.unique_resource_ids - config.high_resource_diversity_threshold + 1,
                20,
            )
            reasons.append(
                BotReason(
                    code="HIGH_RESOURCE_DIVERSITY",
                    category=BotReasonCategory.RESOURCE_DIVERSITY,
                    description=(
                        f"{features.unique_resource_ids} distinct resource IDs were "
                        "accessed by this client. Diversity alone is not malicious."
                    ),
                    severity=BotReasonSeverity.LOW,
                    evidence_count=features.unique_resource_ids,
                    score_contribution=contribution,
                    details={"threshold": config.high_resource_diversity_threshold},
                )
            )
            factors.append(
                BotScoreFactor(
                    factor_name="resource_diversity",
                    contribution=contribution,
                    evidence_count=features.unique_resource_ids,
                    description="Elevated distinct resource-ID access.",
                )
            )

    # 7. Stable, narrow repetition with a consistent User-Agent suggests
    #    automation but remains a benign candidate, not verified or malicious.
    path_counts = Counter(event.path for event in events)
    dominant_path, dominant_count = path_counts.most_common(1)[0] if path_counts else (None, 0)
    dominant_share = (dominant_count / request_count) if request_count else 0.0
    observed_uas = {event.user_agent for event in events if event.user_agent}
    stable_ua = bool(observed_uas) and not ua_request_ids
    stable_repetition = (
        request_count >= config.stable_repetition_min_requests
        and dominant_share >= config.stable_repetition_min_share
        and stable_ua
    )
    if stable_repetition:
        contribution = config.stable_repetition_weight
        reasons.append(
            BotReason(
                code="STABLE_REPEATED_REQUEST_PATTERN",
                category=BotReasonCategory.AUTOMATION_CHARACTERISTIC,
                description=(
                    "A consistent User-Agent and a repeated request path were "
                    "observed. This is consistent with scheduled automation and is "
                    "not evidence of malicious intent."
                ),
                severity=BotReasonSeverity.INFO,
                evidence_count=request_count,
                score_contribution=contribution,
                details={
                    "dominant_path_share": round(dominant_share, 2),
                    "minimum_requests": config.stable_repetition_min_requests,
                },
            )
        )
        factors.append(
            BotScoreFactor(
                factor_name="stable_repetition",
                contribution=contribution,
                evidence_count=request_count,
                description="Stable User-Agent with a dominant repeated request path.",
            )
        )
        automation_indicators.append("STABLE_REPEATED_REQUEST_PATTERN")
        if stable_ua:
            reasons.append(
                BotReason(
                    code="STABLE_USER_AGENT",
                    category=BotReasonCategory.USER_AGENT,
                    description=(
                        "All observed User-Agent values for this client matched its "
                        "most frequent value. This is a neutral stability signal."
                    ),
                    severity=BotReasonSeverity.INFO,
                    evidence_count=request_count,
                    score_contribution=0.0,
                    request_ids=_opaque_request_ids([event.request_id for event in events])[:max_refs],
                )
            )

    # 8. Evidence-quality reasons never add risk by themselves.
    if client_ip is None:
        reasons.append(
            BotReason(
                code="MISSING_CLIENT_ATTRIBUTION",
                category=BotReasonCategory.EVIDENCE_QUALITY,
                description=(
                    "These requests lacked usable client IP attribution; no client "
                    "identity was fabricated."
                ),
                severity=BotReasonSeverity.INFO,
                evidence_count=request_count,
                score_contribution=0.0,
                request_ids=_opaque_request_ids([event.request_id for event in events])[:max_refs],
            )
        )
    elif request_count < config.minimum_requests_for_classification:
        reasons.append(
            BotReason(
                code="INSUFFICIENT_EVIDENCE",
                category=BotReasonCategory.EVIDENCE_QUALITY,
                description=(
                    f"Only {request_count} request(s) were available for this client; "
                    f"fewer than the {config.minimum_requests_for_classification} "
                    "requests required for a confident behavioural classification."
                ),
                severity=BotReasonSeverity.INFO,
                evidence_count=request_count,
                score_contribution=0.0,
                request_ids=_opaque_request_ids([event.request_id for event in events])[:max_refs],
            )
        )

    if shared_ip_attribution or cross_actor_evidence_dropped:
        reasons.append(
            BotReason(
                code="SHARED_IP_ATTRIBUTION_AMBIGUOUS",
                category=BotReasonCategory.EVIDENCE_QUALITY,
                description=(
                    "Multiple actor identities or unattributed requests were observed "
                    "for this network address. The IP is not an individual identity; "
                    "cross-actor evidence was not used against unrelated actors."
                ),
                severity=BotReasonSeverity.INFO,
                evidence_count=request_count,
                score_contribution=0.0,
                request_ids=_opaque_request_ids([event.request_id for event in events])[:max_refs],
                details={
                    "actor_available": bool(actor_key),
                    "cross_actor_evidence_dropped": cross_actor_evidence_dropped,
                },
            )
        )

    bot_risk_score = round(
        min(100.0, max(0.0, sum(factor.contribution for factor in factors))), 1
    )

    override_triggered = False
    score_threshold_with_strong_evidence = False
    strong_evidence_conservative = False
    # A grouped brute-force reason is authoritative evidence even if a future
    # refactor stops setting the `strong_suspicious_signal` flag alongside it.
    has_repeated_auth_failures = any(
        reason.code == "REPEATED_AUTHENTICATION_FAILURES" for reason in reasons
    )

    if client_ip is None:
        classification = BotClassification.UNKNOWN
    elif strong_suspicious_signal and config.brute_force_override_enabled:
        classification = BotClassification.AUTOMATION_SUSPICIOUS
        override_triggered = True
    elif strong_suspicious_signal and bot_risk_score >= config.suspicious_score_threshold:
        classification = BotClassification.AUTOMATION_SUSPICIOUS
        score_threshold_with_strong_evidence = True
    elif strong_suspicious_signal or has_repeated_auth_failures:
        # Before: with the override disabled and the score below threshold, this
        # branch fell through to automation_indicators / request_count and could
        # label grouped brute-force evidence as human_like. After: strong
        # brute-force evidence is never human_like. The override remains the only
        # route to override-driven automation_suspicious, so when it is disabled
        # and the score is low we use the conservative non-human UNKNOWN class.
        # This is an evidence assessment only; no enforcement is activated here.
        classification = BotClassification.UNKNOWN
        strong_evidence_conservative = True
    elif automation_indicators:
        classification = BotClassification.AUTOMATION_BENIGN_CANDIDATE
    elif request_count >= config.minimum_requests_for_classification:
        classification = BotClassification.HUMAN_LIKE
    else:
        classification = BotClassification.UNKNOWN

    # Weak supporting signals never produce `automation_suspicious` on their own.
    # Only the two rules above can do so, and both require grouped brute-force evidence.
    if override_triggered:
        reasons.append(
            BotReason(
                code="BRUTE_FORCE_OVERRIDE",
                category=BotReasonCategory.AUTHENTICATION,
                description=(
                    "Grouped brute-force evidence triggered automation_suspicious "
                    "under the explicit override rule; this is separate from the "
                    "bot score threshold."
                ),
                severity=BotReasonSeverity.INFO,
                score_contribution=0.0,
                details={
                    "bot_risk_score": bot_risk_score,
                    "suspicious_score_threshold": config.suspicious_score_threshold,
                    "override_enabled": True,
                },
            )
        )
    elif score_threshold_with_strong_evidence:
        reasons.append(
            BotReason(
                code="SCORE_THRESHOLD_WITH_STRONG_EVIDENCE",
                category=BotReasonCategory.AUTHENTICATION,
                description=(
                    "The bot score reached the configured threshold and grouped "
                    "brute-force evidence was present; the override was not used."
                ),
                severity=BotReasonSeverity.INFO,
                score_contribution=0.0,
                details={
                    "bot_risk_score": bot_risk_score,
                    "suspicious_score_threshold": config.suspicious_score_threshold,
                    "override_enabled": False,
                },
            )
        )

    evidence_references: List[BotEvidenceReference] = []
    seen_references = set()
    for reason in reasons:
        for request_id in reason.request_ids:
            key = (request_id, reason.code)
            if key in seen_references:
                continue
            seen_references.add(key)
            evidence_references.append(
                BotEvidenceReference(
                    request_id=request_id,
                    source=reason.code,
                    observed_at=opaque_timestamps.get(request_id),
                )
            )
        if len(evidence_references) >= max_refs:
            break
    evidence_references = evidence_references[:max_refs]

    classification_note = ""
    if override_triggered:
        classification_note = (
            f" Classification used BRUTE_FORCE_OVERRIDE (score {bot_risk_score:.1f} "
            f"vs threshold {config.suspicious_score_threshold:.1f})."
        )
    elif score_threshold_with_strong_evidence:
        classification_note = (
            " Classification used SCORE_THRESHOLD_WITH_STRONG_EVIDENCE "
            "(override disabled)."
        )
    elif strong_evidence_conservative:
        classification_note = (
            " Brute-force evidence was scored but the override is disabled and "
            "the score threshold was not reached; the traffic was conservatively "
            "classified as unknown rather than human_like. No enforcement was "
            "activated."
        )
    elif strong_suspicious_signal and not config.brute_force_override_enabled:
        classification_note = (
            " Brute-force evidence was scored but the override is disabled and "
            "the score threshold was not reached."
        )
    elif not strong_suspicious_signal:
        classification_note = (
            " No strong suspicious evidence was present; supporting bot-like "
            "signals do not imply malicious intent."
        )

    summary = (
        f"Bot risk score {bot_risk_score:.1f} classified as {classification.value} "
        f"from {request_count} attributed request(s) and {len(factors)} score "
        f"factor(s).{classification_note} This is an evidence assessment, not a "
        "mitigation or enforcement decision."
    )

    return BotAnalysisResult(
        client_ip=client_ip,
        actor_id=_representative_actor(events),
        bot_risk_score=bot_risk_score,
        classification=classification,
        reasons=reasons,
        score_factors=factors,
        evidence_references=evidence_references,
        request_count=request_count,
        first_seen=first_seen,
        last_seen=last_seen,
        observation_window_seconds=observation_seconds,
        summary=summary,
    )


def analyze_traffic_for_bot_detection(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    page: int = 1,
    page_size: int = 200,
    max_records: int = 1000,
    include_behavioral_risk: bool = False,
    scoring_config: Optional[BotScoringConfig] = None,
    rate_detector_config: Optional[RateAnomalyDetectorConfig] = None,
    brute_force_detector_config: Optional[BruteForceDetectorConfig] = None,
    db: Optional[Session] = None,
) -> BotDetectionResponse:
    """Analyze stored traffic logs and return deterministic bot assessments."""
    if start_time is not None and end_time is not None and start_time > end_time:
        raise ValueError("start_time must be earlier than or equal to end_time")

    config = scoring_config or BotScoringConfig()
    safe_page = max(1, page)
    safe_page_size = min(max(1, page_size), 500)
    safe_max_records = min(max(1, max_records), MAX_RECORD_HARD_LIMIT)

    records, truncated = _fetch_traffic_records(
        method=method,
        path=path,
        status_code=status_code,
        client_ip=client_ip,
        start_time=start_time,
        end_time=end_time,
        page=safe_page,
        page_size=safe_page_size,
        max_records=safe_max_records,
        db=db,
    )

    limits = BotAnalysisLimits(
        requested_page=safe_page,
        requested_page_size=safe_page_size,
        max_records=safe_max_records,
        records_analyzed=len(records),
        truncated=truncated,
    )

    if not records:
        return BotDetectionResponse(
            results=[],
            total_clients=0,
            total_events_analyzed=0,
            analysis_window_start=None,
            analysis_window_end=None,
            requested_start_time=_ensure_utc(start_time) if start_time else None,
            requested_end_time=_ensure_utc(end_time) if end_time else None,
            limits=limits,
            summary=BotAnalysisSummary(
                summary=(
                    "No traffic events matched the query criteria; no bot "
                    "classification was produced."
                )
            ),
        )

    events: List[BehaviorEvent] = []
    rate_events = []
    brute_events = []
    malformed_records_skipped = 0

    for record in records:
        try:
            event = convert_traffic_log_to_behavior_event(record, headers=None)
            if event is not None:
                events.append(event)
        except Exception as exc:
            malformed_records_skipped += 1
            logger.warning("Skipping malformed traffic record in bot analysis: %s", exc)

        try:
            rate_event = convert_traffic_log_to_rate_anomaly_event(record, headers=None)
            if rate_event is not None:
                rate_events.append(rate_event)
        except Exception:
            pass

        try:
            brute_event = convert_traffic_log_to_bruteforce_event(record, headers=None)
            if brute_event is not None:
                brute_events.append(brute_event)
        except Exception:
            pass

    if not events:
        return BotDetectionResponse(
            results=[],
            total_clients=0,
            total_events_analyzed=0,
            analysis_window_start=None,
            analysis_window_end=None,
            requested_start_time=_ensure_utc(start_time) if start_time else None,
            requested_end_time=_ensure_utc(end_time) if end_time else None,
            limits=limits,
            summary=BotAnalysisSummary(
                malformed_records_skipped=malformed_records_skipped,
                summary=(
                    "No usable traffic events were available for bot analysis after "
                    "defensive record filtering."
                ),
            ),
        )

    # Run existing detectors; a detector failure degrades to no evidence rather
    # than inventing a high-risk classification.
    rate_by_client: Dict[str, List[Any]] = defaultdict(list)
    brute_by_client: Dict[str, List[Any]] = defaultdict(list)
    try:
        rate_result = analyze_rate_events(rate_events, detector_config=rate_detector_config)
        for evidence in rate_result.evidences:
            if evidence.client_ip:
                rate_by_client[evidence.client_ip.strip()].append(evidence)
    except Exception as exc:
        logger.warning("Bot rate-anomaly detector skipped: %s", exc)

    try:
        brute_result = analyze_bruteforce_events(
            brute_events, detector_config=brute_force_detector_config
        )
        for evidence in brute_result.evidences:
            if evidence.client_ip:
                brute_by_client[evidence.client_ip.strip()].append(evidence)
    except Exception as exc:
        logger.warning("Bot brute-force detector skipped: %s", exc)

    events_by_group: Dict[ClientGroupKey, List[BehaviorEvent]] = defaultdict(list)
    events_by_client: Dict[Optional[str], List[BehaviorEvent]] = defaultdict(list)
    for event in events:
        group_key = _client_group_key(event)
        events_by_group[group_key].append(event)
        events_by_client[group_key[0]].append(event)

    actors_by_ip: Dict[str, Set[Optional[str]]] = defaultdict(set)
    for (ip, actor), _group_events in events_by_group.items():
        if ip:
            actors_by_ip[ip].add(actor)
    shared_ips: Set[str] = {
        ip for ip, actors in actors_by_ip.items() if len(actors) > 1
    }

    group_by_request_id: Dict[str, ClientGroupKey] = {
        event.request_id: group_key
        for group_key, group_events in events_by_group.items()
        for event in group_events
    }

    features_by_group: Dict[ClientGroupKey, BehaviorFeatures] = {}
    for group_key, group_events in events_by_group.items():
        group_feature_result = extract_features_for_events(group_events)
        if group_feature_result.client_features:
            features_by_group[group_key] = group_feature_result.client_features[0]

    ua_signals: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"request_ids": [], "values": set()}
    )
    pattern_signals: Dict[str, Dict[str, List[str]]] = defaultdict(
        lambda: {"method_ids": [], "path_ids": []}
    )
    historical_signals: Dict[str, Dict[str, List[str]]] = defaultdict(
        lambda: {"method_ids": [], "path_ids": []}
    )

    try:
        for finding in analyze_user_agent_frequency(events):
            if finding.get("is_anomaly") is not True:
                continue
            client = finding.get("client_ip")
            value = finding.get("user_agent")
            if not client:
                continue
            client_events = events_by_client.get(client, [])
            request_ids = [
                event.request_id for event in client_events if event.user_agent == value
            ]
            ua_signals[client]["request_ids"].extend(request_ids)
            ua_signals[client]["values"].add(value)
    except Exception as exc:
        logger.warning("Bot User-Agent review skipped: %s", exc)

    try:
        for finding in analyze_http_method_frequency(events):
            if finding.get("is_anomaly") is not True or not finding.get("client_ip"):
                continue
            client = finding["client_ip"]
            value = finding.get("http_method")
            request_ids = [
                event.request_id
                for event in events_by_client.get(client, [])
                if event.method == value
            ]
            pattern_signals[client]["method_ids"].extend(request_ids)

        for finding in analyze_request_path_frequency(events):
            if finding.get("is_anomaly") is not True or not finding.get("client_ip"):
                continue
            client = finding["client_ip"]
            value = finding.get("request_path")
            request_ids = [
                event.request_id
                for event in events_by_client.get(client, [])
                if event.path == value
            ]
            pattern_signals[client]["path_ids"].extend(request_ids)
    except Exception as exc:
        logger.warning("Bot request-pattern review skipped: %s", exc)

    client_ips = sorted(ip for ip in events_by_client if ip)
    for finding in _collect_historical_findings(
        events=events,
        client_ips=client_ips,
        end_time=end_time,
        db=db,
    ):
        if finding.get("is_anomaly") is not True or not finding.get("client_ip"):
            continue
        client = finding["client_ip"]
        if "http_method" in finding:
            value = finding["http_method"]
            request_ids = [
                event.request_id
                for event in events_by_client.get(client, [])
                if event.method == value
            ]
            historical_signals[client]["method_ids"].extend(request_ids)
        elif "request_path" in finding:
            value = finding["request_path"]
            request_ids = [
                event.request_id
                for event in events_by_client.get(client, [])
                if event.path == value
            ]
            historical_signals[client]["path_ids"].extend(request_ids)

    behavior_by_client: Dict[str, Any] = {}
    if include_behavioral_risk:
        try:
            behavior_response = analyze_traffic_for_behavior_risk(
                start_time=start_time,
                end_time=end_time,
                method=method,
                path=path,
                status_code=status_code,
                client_ip=client_ip,
                page=safe_page,
                page_size=safe_page_size,
                db=db,
            )
            for result in behavior_response.results:
                if result.client_ip:
                    behavior_by_client[result.client_ip] = result
        except Exception as exc:
            logger.warning("Separate behavioural risk context skipped: %s", exc)

    timestamps_by_request = {
        event.request_id: _ensure_utc(event.timestamp) for event in events
    }

    results: List[BotAnalysisResult] = []
    for group_key in sorted(events_by_group, key=lambda key: (key[0] or "", key[1] or "")):
        client, actor_key = group_key
        shared_ip_attribution = bool(client and client in shared_ips)

        rate_evidences, rate_ambiguous = _filter_detector_evidences(
            rate_by_client.get(client, []), group_key, shared_ips, group_by_request_id
        )
        brute_evidences, brute_ambiguous = _filter_detector_evidences(
            brute_by_client.get(client, []), group_key, shared_ips, group_by_request_id
        )

        result = _score_client(
            client_ip=client,
            actor_key=actor_key,
            events=events_by_group[group_key],
            features=features_by_group.get(group_key),
            rate_evidences=rate_evidences,
            brute_evidences=brute_evidences,
            ua_signal=_signals_for_group(
                ua_signals.get(client, {}), group_key, group_by_request_id, ("request_ids",)
            ),
            pattern_signal=_signals_for_group(
                pattern_signals.get(client, {}),
                group_key,
                group_by_request_id,
                ("method_ids", "path_ids"),
            ),
            historical_signal=_signals_for_group(
                historical_signals.get(client, {}),
                group_key,
                group_by_request_id,
                ("method_ids", "path_ids"),
            ),
            config=config,
            timestamps_by_request=timestamps_by_request,
            shared_ip_attribution=shared_ip_attribution,
            cross_actor_evidence_dropped=rate_ambiguous or brute_ambiguous,
        )
        # Behavioural context is IP-scoped; do not attach it to split actor groups.
        behavior_result = (
            behavior_by_client.get(client)
            if client and not shared_ip_attribution
            else None
        )
        if behavior_result is not None:
            result.behavioral_risk = BehavioralRiskContext(
                risk_score=behavior_result.risk_score,
                risk_level=behavior_result.risk_level.value,
                explanation=behavior_result.explanation,
            )
        results.append(result)

    all_timestamps = [_ensure_utc(event.timestamp) for event in events]
    classification_counts = Counter(result.classification.value for result in results)
    override_count = sum(
        1
        for result in results
        if any(reason.code == "BRUTE_FORCE_OVERRIDE" for reason in result.reasons)
    )
    summary_text = (
        f"Completed bot detection analysis for {len(results)} client group(s) "
        f"across {len(events)} traffic event(s). "
        f"{classification_counts.get(BotClassification.HUMAN_LIKE.value, 0)} human-like, "
        f"{classification_counts.get(BotClassification.AUTOMATION_BENIGN_CANDIDATE.value, 0)} benign automation candidate(s), "
        f"{classification_counts.get(BotClassification.AUTOMATION_SUSPICIOUS.value, 0)} suspicious automation candidate(s), "
        f"{classification_counts.get(BotClassification.UNKNOWN.value, 0)} unknown. "
        f"{override_count} suspicious classification(s) used the explicit brute-force override. "
        "Supporting bot-like signals alone never imply malicious intent. "
        "No blocking, throttling, or other mitigation is represented."
    )

    return BotDetectionResponse(
        results=results,
        total_clients=len(results),
        total_events_analyzed=len(events),
        analysis_window_start=min(all_timestamps) if all_timestamps else None,
        analysis_window_end=max(all_timestamps) if all_timestamps else None,
        requested_start_time=_ensure_utc(start_time) if start_time else None,
        requested_end_time=_ensure_utc(end_time) if end_time else None,
        limits=limits,
        summary=BotAnalysisSummary(
            total_clients=len(results),
            total_requests_analyzed=len(events),
            human_like_clients=classification_counts.get(
                BotClassification.HUMAN_LIKE.value, 0
            ),
            benign_automation_candidates=classification_counts.get(
                BotClassification.AUTOMATION_BENIGN_CANDIDATE.value, 0
            ),
            suspicious_automation_candidates=classification_counts.get(
                BotClassification.AUTOMATION_SUSPICIOUS.value, 0
            ),
            unknown_clients=classification_counts.get(BotClassification.UNKNOWN.value, 0),
            malformed_records_skipped=malformed_records_skipped,
            brute_force_override_count=override_count,
            summary=summary_text,
        ),
    )
