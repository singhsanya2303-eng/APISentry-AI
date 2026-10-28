"""
Behavioral Analysis & Feature Extraction Service — Module 7, Step 1.

Extracts normalized behavioral events and deterministic client-level features
from raw API traffic metadata and detection signals.

PIPELINE:
    APITrafficLog / Detection Signals
                  ↓
    convert_traffic_log_to_behavior_event
                  ↓
            BehaviorEvent
                  ↓
      extract_features_for_events
                  ↓
    BehaviorFeatures & BehaviorAnalysisResult

SECURITY CONTRACT:
  - Authorization headers, Bearer tokens, cookies, API keys, passwords,
    and any credential-bearing data are NEVER inspected, stored, logged, or exposed.
  - actor_id is OPTIONAL context, extracted strictly through safe channels.
  - client_ip is the primary attribution signal. Missing client IPs are
    never fabricated.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.models.traffic import APITrafficLog
from app.schemas.behavior import (
    BehaviorEvent,
    BehaviorFeatures,
    BehaviorAnalysisResult,
    BehaviorRiskAnalysisResponse,
    RiskScoreResult,
)
from app.detection.risk_scorer import RiskScorer, RiskScoringConfig
from app.services.resource_extractor import (
    extract_candidate_resources,
    extract_safe_actor_id,
)
from app.services.traffic_service import (
    get_traffic_logs,
    get_historical_traffic_logs,
)
from app.services.historical_request_pattern_service import (
    analyze_historical_request_patterns,
    get_historical_window,
)

logger = logging.getLogger("apisentry.analysis.behavior")


def _count_user_agent_review_clients(logs: List[APITrafficLog]) -> int:
    """Count client IPs flagged for User-Agent review in the current batch.

    This is diagnostic context only: aggregate User-Agent findings do not identify
    specific requests and must not be converted into request-level risk signals.
    """
    if not logs:
        return 0

    try:
        from app.services.user_agent_anomaly_service import analyze_user_agent_frequency
    except Exception as exc:
        logger.warning("User-Agent anomaly detector unavailable: %s", exc)
        return 0

    events: List[BehaviorEvent] = []
    for log in logs:
        try:
            event = convert_traffic_log_to_behavior_event(log, headers=None)
            if event is not None:
                events.append(event)
        except Exception:
            # A malformed log should not stop analysis of the remaining batch.
            continue

    try:
        findings = analyze_user_agent_frequency(events)
    except Exception as exc:
        logger.warning("User-Agent anomaly analysis skipped due to error: %s", exc)
        return 0

    # Count clients, not individual UA strings. Do not log raw IPs or User-Agent values.
    return len({
        finding.get("client_ip")
        for finding in findings
        if finding.get("is_anomaly") is True
        and isinstance(finding.get("client_ip"), str)
        and finding.get("client_ip", "").strip()
    })


def _count_request_pattern_review_clients(logs: List[APITrafficLog]) -> int:
    """Count clients with HTTP-method or request-path frequency review findings.

    These are aggregate, batch-level review signals. They are intentionally not
    converted into request-level detection signals and do not directly affect risk
    scores. The detectors compare values within the supplied batch; they do not
    maintain historical per-client baselines.
    """
    if not logs:
        return 0

    try:
        from app.services.request_pattern_anomaly_service import (
            analyze_http_method_frequency,
            analyze_request_path_frequency,
        )
    except Exception as exc:
        logger.warning("Request-pattern anomaly detector unavailable: %s", exc)
        return 0

    events: List[BehaviorEvent] = []
    for log in logs:
        try:
            event = convert_traffic_log_to_behavior_event(log, headers=None)
            if event is not None:
                events.append(event)
        except Exception:
            continue

    if not events:
        return 0

    try:
        method_findings = analyze_http_method_frequency(events)
        path_findings = analyze_request_path_frequency(events)
    except Exception as exc:
        logger.warning("Request-pattern anomaly analysis skipped due to error: %s", exc)
        return 0

    flagged_clients = {
        finding.get("client_ip")
        for finding in [*method_findings, *path_findings]
        if finding.get("is_anomaly") is True
        and isinstance(finding.get("client_ip"), str)
        and finding.get("client_ip", "").strip()
    }
    return len(flagged_clients)


def _derive_signals_from_logs(
    logs: List[APITrafficLog],
    existing_signals: Dict[str, Dict[str, str]],
) -> Dict[str, Dict[str, str]]:
    """
    Run the BOLA, brute-force, and rate-anomaly detectors over *logs* and
    translate each detector's findings into the signals_map format consumed
    by extract_features_from_traffic_logs.

    Design guarantees:
    - Caller-supplied signals in *existing_signals* are NEVER overwritten;
      detector-derived signals only fill gaps for request_ids absent from
      existing_signals.
    - Each detector is run exactly once over the full log list (no N+1).
    - Detector request_id lists from evidence are the ground-truth for
      per-request attribution; no fabrication occurs.
    - If a detector produces no findings, its contribution to the map is zero.
    - Import is deferred inside the function to avoid circular-import risk.
    """
    if not logs:
        return {}

    derived: Dict[str, Dict[str, str]] = {}

    # --- BOLA detector -------------------------------------------------
    try:
        from app.services.bola_analysis_service import analyze_events_directly as bola_analyze
        from app.services.resource_extractor import extract_from_traffic_log
        from app.schemas.bola import DetectionVerdict as BolaVerdict

        bola_events = []
        for log in logs:
            try:
                ev = extract_from_traffic_log(log, headers=None)
                bola_events.append(ev)
            except Exception:
                pass  # malformed logs are skipped silently

        if bola_events:
            bola_result = bola_analyze(bola_events)
            if bola_result.verdict == BolaVerdict.SUSPICIOUS_BOLA_CANDIDATE:
                for evidence in bola_result.evidences:
                    for req_id in evidence.request_ids:
                        if req_id and req_id not in existing_signals:
                            derived[req_id] = {
                                "detection_source": "bola",
                                "detection_verdict": "suspicious_bola_candidate",
                            }
    except Exception as exc:
        logger.warning("BOLA detector integration skipped due to error: %s", exc)

    # --- Brute-force detector ------------------------------------------
    try:
        from app.services.bruteforce_analysis_service import (
            analyze_events_directly as bf_analyze,
            convert_traffic_log_to_bruteforce_event,
        )
        from app.schemas.bruteforce import BruteForceVerdict

        bf_events = []
        for log in logs:
            try:
                ev = convert_traffic_log_to_bruteforce_event(log, headers=None)
                if ev is not None:
                    bf_events.append(ev)
            except Exception:
                pass

        if bf_events:
            bf_result = bf_analyze(bf_events)
            if bf_result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE:
                for evidence in bf_result.evidences:
                    for req_id in evidence.request_ids:
                        if req_id and req_id not in existing_signals and req_id not in derived:
                            derived[req_id] = {
                                "detection_source": "bruteforce",
                                "detection_verdict": "suspicious_bruteforce_candidate",
                            }
    except Exception as exc:
        logger.warning("Brute-force detector integration skipped due to error: %s", exc)

    # --- Rate-anomaly detector ----------------------------------------
    try:
        from app.services.rate_anomaly_analysis_service import (
            analyze_events_directly as ra_analyze,
            convert_traffic_log_to_rate_anomaly_event,
        )
        from app.schemas.rate_anomaly import RateAnomalyVerdict

        ra_events = []
        for log in logs:
            try:
                ev = convert_traffic_log_to_rate_anomaly_event(log, headers=None)
                if ev is not None:
                    ra_events.append(ev)
            except Exception:
                pass

        if ra_events:
            ra_result = ra_analyze(ra_events)
            if ra_result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY:
                for evidence in ra_result.evidences:
                    for req_id in evidence.request_ids:
                        if req_id and req_id not in existing_signals and req_id not in derived:
                            derived[req_id] = {
                                "detection_source": "rate_anomaly",
                                "detection_verdict": "suspicious_rate_anomaly",
                            }
    except Exception as exc:
        logger.warning("Rate-anomaly detector integration skipped due to error: %s", exc)

    return derived


def _ensure_utc(ts: Optional[datetime]) -> datetime:
    """Ensure datetime is timezone-aware in UTC."""
    if ts is None:
        return datetime.now(timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def convert_traffic_log_to_behavior_event(
    log: APITrafficLog,
    headers: Optional[Dict[str, str]] = None,
    detection_source: Optional[str] = None,
    detection_verdict: Optional[str] = None,
) -> Optional[BehaviorEvent]:
    """
    Safely convert an APITrafficLog ORM object into a normalized BehaviorEvent schema.

    Reuses existing path normalization and resource extraction from Module 4:
    - Normalizes path into endpoint templates (e.g. /users/{user_id})
    - Extracts candidate resource_type and resource_id
    - Extracts safe actor_id without inspecting credential headers
    """
    if log is None:
        return None

    request_id = getattr(log, "request_id", None)
    if not request_id or not isinstance(request_id, str):
        raise ValueError("Missing or invalid request_id in traffic log")

    path = getattr(log, "path", None)
    if not path or not isinstance(path, str):
        raise ValueError("Missing or invalid path in traffic log")

    method = getattr(log, "method", "GET")
    if not method or not isinstance(method, str):
        method = "GET"
    method = method.upper()

    timestamp = _ensure_utc(getattr(log, "timestamp", None))

    raw_ip = getattr(log, "client_ip", None)
    client_ip: Optional[str] = None
    if raw_ip and isinstance(raw_ip, str) and raw_ip.strip():
        client_ip = raw_ip.strip()

    status_code = getattr(log, "status_code", None)
    if status_code is None or not isinstance(status_code, int):
        raise ValueError("Missing or invalid status_code in traffic log")

    # Reuse existing safe resource and actor extractors
    extracted_resources, normalized_endpoint = extract_candidate_resources(path)
    primary_resource = extracted_resources[-1] if extracted_resources else None
    resource_type = primary_resource.resource_type if primary_resource else None
    resource_id = primary_resource.resource_id if primary_resource else None

    query_params = getattr(log, "query_params", None)
    actor_id = extract_safe_actor_id(headers=headers, query_params=query_params)

    # Copy safe User-Agent metadata from the traffic log.
    # Never inspect or store authorization headers, cookies, or tokens.
    user_agent = getattr(log, "user_agent", None)
    if not isinstance(user_agent, str) or not user_agent.strip():
        user_agent = None
    else:
        user_agent = user_agent.strip()[:500]

    return BehaviorEvent(
        request_id=request_id,
        timestamp=timestamp,
        client_ip=client_ip,
        actor_id=actor_id,
        method=method,
        path=path,
        normalized_endpoint=normalized_endpoint,
        status_code=status_code,
        resource_type=resource_type,
        resource_id=resource_id,
        detection_source=detection_source,
        detection_verdict=detection_verdict,
        user_agent=user_agent,
    )


def extract_features_for_events(
    events: List[BehaviorEvent]
) -> BehaviorAnalysisResult:
    """
    Extract deterministic client-level behavioral features from a list of BehaviorEvent records.

    Calculates:
    - Total request counts
    - Unique endpoints, resource types, and resource IDs
    - Success / failure / auth failure rates
    - Observation window (first_seen, last_seen, observation_window_seconds)
    - Contributing detection signal counts (BOLA, brute force, rate anomaly)
    """
    if not events:
        return BehaviorAnalysisResult(
            analyzed_event_count=0,
            distinct_client_count=0,
            distinct_actor_count=0,
            client_features=[],
            summary="No behavioral events provided for feature extraction."
        )

    total_events = len(events)

    # Group events by client_ip
    grouped_by_client: Dict[str, List[BehaviorEvent]] = {}
    missing_ip_count = 0

    for event in events:
        if not event or not event.client_ip or not event.client_ip.strip():
            missing_ip_count += 1
            continue
        client_ip = event.client_ip.strip()
        grouped_by_client.setdefault(client_ip, []).append(event)

    client_features_list: List[BehaviorFeatures] = []
    distinct_actors: Set[str] = set()

    for client_ip, client_events in grouped_by_client.items():
        sorted_events = sorted(client_events, key=lambda e: _ensure_utc(e.timestamp))

        total_reqs = len(sorted_events)
        unique_eps = len(set(e.normalized_endpoint for e in sorted_events))
        unique_res_types = len(set(e.resource_type for e in sorted_events if e.resource_type))
        unique_res_ids = len(set(e.resource_id for e in sorted_events if e.resource_id))

        succ_count = sum(1 for e in sorted_events if 200 <= e.status_code < 300)
        fail_count = sum(1 for e in sorted_events if e.status_code >= 400)
        auth_fail_count = sum(1 for e in sorted_events if e.status_code == 401)

        # Detection signal counts
        rate_anom_count = sum(
            1 for e in sorted_events
            if e.detection_source == "rate_anomaly" or e.detection_verdict == "suspicious_rate_anomaly"
        )
        bola_count = sum(
            1 for e in sorted_events
            if e.detection_source == "bola" or e.detection_verdict == "suspicious_bola_candidate"
        )
        bruteforce_count = sum(
            1 for e in sorted_events
            if e.detection_source == "bruteforce" or e.detection_verdict == "suspicious_bruteforce_candidate"
        )

        first_seen = _ensure_utc(sorted_events[0].timestamp)
        last_seen = _ensure_utc(sorted_events[-1].timestamp)
        obs_duration = round(max(0.0, (last_seen - first_seen).total_seconds()), 2)

        # Representative actor ID if available
        actors = [e.actor_id for e in sorted_events if e.actor_id]
        rep_actor = max(set(actors), key=actors.count) if actors else None
        if rep_actor:
            distinct_actors.add(rep_actor)

        features = BehaviorFeatures(
            client_ip=client_ip,
            actor_id=rep_actor,
            total_requests=total_reqs,
            unique_endpoints=unique_eps,
            unique_resource_types=unique_res_types,
            unique_resource_ids=unique_res_ids,
            failed_request_count=fail_count,
            successful_request_count=succ_count,
            authentication_failure_count=auth_fail_count,
            rate_anomaly_count=rate_anom_count,
            bola_candidate_count=bola_count,
            brute_force_candidate_count=bruteforce_count,
            first_seen=first_seen,
            last_seen=last_seen,
            observation_window_seconds=obs_duration,
        )
        client_features_list.append(features)

    summary = (
        f"Extracted behavioral features for {len(client_features_list)} distinct client(s) "
        f"across {total_events} analyzed event(s)."
    )
    if missing_ip_count > 0:
        summary += f" ({missing_ip_count} event(s) lacked client IP attribution)."

    return BehaviorAnalysisResult(
        analyzed_event_count=total_events,
        distinct_client_count=len(client_features_list),
        distinct_actor_count=len(distinct_actors),
        client_features=client_features_list,
        summary=summary,
    )


def extract_features_from_traffic_logs(
    logs: List[APITrafficLog],
    headers_map: Optional[Dict[str, Dict[str, str]]] = None,
    signals_map: Optional[Dict[str, Dict[str, str]]] = None,
) -> BehaviorAnalysisResult:
    """
    Convenience method to convert a list of APITrafficLog records and extract behavioral features.

    Defensively skips individual malformed records without failing the entire batch.
    """
    headers_map = headers_map or {}
    signals_map = signals_map or {}

    events: List[BehaviorEvent] = []
    for log in logs:
        try:
            req_id = getattr(log, "request_id", None)
            headers = headers_map.get(req_id) if req_id else None
            signals = signals_map.get(req_id, {}) if req_id else {}

            event = convert_traffic_log_to_behavior_event(
                log=log,
                headers=headers,
                detection_source=signals.get("detection_source"),
                detection_verdict=signals.get("detection_verdict"),
            )
            if event is not None:
                events.append(event)
        except Exception as exc:
            logger.warning(
                "Skipping malformed traffic log entry in behavioral feature extraction (request_id=%s): %s",
                getattr(log, "request_id", "unknown"),
                exc,
            )
            continue

    return extract_features_for_events(events)


def analyze_traffic_for_behavior_risk(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    page: int = 1,
    page_size: int = 200,
    scoring_config: Optional[RiskScoringConfig] = None,
    headers_map: Optional[Dict[str, Dict[str, str]]] = None,
    signals_map: Optional[Dict[str, Dict[str, str]]] = None,
    db: Optional[Session] = None,
) -> BehaviorRiskAnalysisResponse:
    """
    End-to-end service integration workflow for behavioral analysis and deterministic risk scoring.

    Pipeline:
    1. Query database traffic logs using filter criteria via traffic_service.get_traffic_logs.
    2. If the caller did not explicitly supply signals_map, run the BOLA, brute-force, and
       rate-anomaly detectors over the retrieved logs to derive detection signals automatically.
       Caller-supplied signals_map values are always preserved and never overwritten.
    3. Extract normalized behavioral events and aggregated BehaviorFeatures per client IP.
    4. Pass BehaviorFeatures into RiskScorer to compute deterministic RiskScoreResult per client.
    5. Assemble and return structured BehaviorRiskAnalysisResponse.
    """
    headers_map = headers_map or {}

    # Track whether the caller explicitly passed a signals_map.
    # None means "not provided" — derive from detectors.
    # {} (empty dict) supplied by the caller means "use no signals" — honour that.
    caller_supplied_signals = signals_map is not None
    signals_map = signals_map if signals_map is not None else {}

    try:
        logs = get_traffic_logs(
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
            db=db,
        )
    except Exception as exc:
        logger.error("Failed to query traffic logs for behavioral risk analysis: %s", exc)
        logs = []

    if not logs:
        return BehaviorRiskAnalysisResponse(
            results=[],
            total_clients=0,
            observation_start=None,
            observation_end=None,
            total_events_analyzed=0,
            summary="No traffic events matching query criteria found for behavioral risk analysis."
        )

   
    # Derive detector signals when the caller did not explicitly supply signals_map.
    # Caller-supplied signals are preserved and take priority.
    user_agent_review_clients = 0
    request_pattern_review_clients = 0
    historical_pattern_review_clients = 0

    if not caller_supplied_signals:
        derived_signals = _derive_signals_from_logs(
            logs, existing_signals=signals_map
        )
        user_agent_review_clients = _count_user_agent_review_clients(logs)
        request_pattern_review_clients = _count_request_pattern_review_clients(logs)

        effective_signals: Dict[str, Dict[str, str]] = {
            **derived_signals,
            **signals_map,
        }
    else:
        # Explicit signals_map means automatic detectors must be skipped.
        effective_signals = signals_map

    # Historical baseline review only; never changes signals or risk scores.
    try:
        observation_end = _ensure_utc(end_time)
        history_start, history_end = get_historical_window(observation_end)

        client_ips = sorted({
            log.client_ip.strip()
            for log in logs
            if isinstance(getattr(log, "client_ip", None), str)
            and log.client_ip.strip()
        })

        historical_logs = (
            get_historical_traffic_logs(
                client_ips=client_ips,
                start_time=history_start,
                end_time=history_end,
                db=db,
            )
            if client_ips
            else []
        )

        historical_findings = analyze_historical_request_patterns(
            current_events=logs,
            historical_events=historical_logs,
        )

        historical_pattern_review_clients = len({
            finding["client_ip"]
            for finding in historical_findings
            if finding.get("is_anomaly") is True
        })

    except Exception as exc:
        logger.warning("Historical request-pattern review failed: %s", exc)
        historical_pattern_review_clients = 0

    analysis_result = extract_features_from_traffic_logs(
        logs=logs,
        headers_map=headers_map,
        signals_map=effective_signals,
    )

    if not analysis_result.client_features:
        return BehaviorRiskAnalysisResponse(
            results=[],
            total_clients=0,
            observation_start=None,
            observation_end=None,
            total_events_analyzed=analysis_result.analyzed_event_count,
            summary="No client-attributed traffic events available for risk scoring after filtering.",
        )

    scorer = RiskScorer(config=scoring_config)
    results: List[RiskScoreResult] = []

    for features in analysis_result.client_features:
        results.append(scorer.score_features(features))

    results.sort(key=lambda r: r.client_ip or "")

    # Calculate observation window before building the response.
    obs_starts = [
        f.first_seen
        for f in analysis_result.client_features
        if f.first_seen
    ]
    obs_ends = [
        f.last_seen
        for f in analysis_result.client_features
        if f.last_seen
    ]

    obs_start = min(obs_starts) if obs_starts else None
    obs_end = max(obs_ends) if obs_ends else None

    summary = (
        f"Completed behavioral risk assessment for {len(results)} client(s) "
        f"across {analysis_result.analyzed_event_count} analyzed event(s)."
    )

    if user_agent_review_clients:
        summary += (
            f" User-Agent review flags were found for "
            f"{user_agent_review_clients} client(s); treat these as review signals, "
            "not proof of account compromise."
        )

    if request_pattern_review_clients:
        summary += (
            f" HTTP-method/request-path review flags were found for "
            f"{request_pattern_review_clients} client(s); treat these as review signals, "
            "not proof of attack."
        )

    if historical_pattern_review_clients:
        summary += (
            f" Historical HTTP-method/request-path baseline flagged "
            f"{historical_pattern_review_clients} client(s) for review; "
            "these are review indicators, not proof of attack."
        )

    return BehaviorRiskAnalysisResponse(
        results=results,
        total_clients=len(results),
        observation_start=obs_start,
        observation_end=obs_end,
        total_events_analyzed=analysis_result.analyzed_event_count,
        summary=summary,
    )
