from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from app.schemas.bola import (
    ResourceAccessEvent,
    DetectionVerdict,
    BolaEvidence,
    BolaDetectionResult,
)
from app.models.traffic import APITrafficLog
from app.services.resource_extractor import extract_from_traffic_log


class BolaDetectorConfig(BaseModel):
    """Configurable detection thresholds for BOLA/IDOR detector."""
    min_distinct_objects: int = Field(default=3, ge=2, description="Minimum distinct object IDs accessed by same actor to trigger BOLA candidate")
    min_extraction_confidence: float = Field(default=0.70, ge=0.0, le=1.0, description="Minimum resource extraction confidence threshold")
    time_window_minutes: Optional[int] = Field(default=60, description="Analysis time window in minutes (optional)")
    require_successful_access: bool = Field(default=False, description="If true, require at least one 2xx status code to flag BOLA candidate")


def check_is_sequential(object_ids: List[str]) -> bool:
    """Check if list of object IDs forms a sequential numeric sequence (e.g. 101, 102, 103)."""
    numeric_ids = []
    for oid in object_ids:
        if oid.isdigit():
            numeric_ids.append(int(oid))
        else:
            return False

    if len(numeric_ids) < 2:
        return False

    sorted_ids = sorted(numeric_ids)
    for i in range(1, len(sorted_ids)):
        if sorted_ids[i] != sorted_ids[i - 1] + 1:
            return False
    return True


class BolaDetector:
    """
    Deterministic BOLA/IDOR Detection Engine.
    Analyzes sequences of ResourceAccessEvent records for suspicious cross-object access patterns by the same actor.
    """

    def __init__(self, config: Optional[BolaDetectorConfig] = None):
        self.config = config or BolaDetectorConfig()

    def analyze_events(self, events: List[ResourceAccessEvent]) -> BolaDetectionResult:
        if not events:
            return BolaDetectionResult(
                verdict=DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR,
                evidences=[],
                analyzed_event_count=0,
                explanation="No traffic events provided for BOLA analysis."
            )

        # Apply time window filter if specified
        valid_events = events
        if self.config.time_window_minutes is not None and events:
            max_ts = max(e.timestamp for e in events)
            min_ts = max_ts - timedelta(minutes=self.config.time_window_minutes)
            valid_events = [e for e in events if e.timestamp >= min_ts]

        missing_actor_count = 0
        candidate_events = []

        for event in valid_events:
            # 1. Skip events without candidate object reference
            if not event.has_object_reference or not event.primary_resource:
                continue

            # 2. Skip low confidence extractions
            if event.primary_resource.confidence < self.config.min_extraction_confidence:
                continue

            # 3. Check actor identity presence
            if not event.actor_id:
                missing_actor_count += 1
                continue

            candidate_events.append(event)

        # Group candidate events by (actor_id, resource_type, normalized_endpoint)
        grouped_events: Dict[Tuple[str, str, str], List[ResourceAccessEvent]] = {}
        for event in candidate_events:
            actor = event.actor_id
            res_type = event.primary_resource.resource_type
            endpoint = event.normalized_endpoint
            key = (actor, res_type, endpoint)
            if key not in grouped_events:
                grouped_events[key] = []
            grouped_events[key].append(event)

        evidences: List[BolaEvidence] = []

        for (actor_id, res_type, endpoint), group_list in grouped_events.items():
            # Order events chronologically
            sorted_group = sorted(group_list, key=lambda x: x.timestamp)
            
            # Distinct object IDs accessed
            raw_ids = [e.primary_resource.resource_id for e in sorted_group if e.primary_resource]
            distinct_ids = []
            for oid in raw_ids:
                if oid not in distinct_ids:
                    distinct_ids.append(oid)

            distinct_count = len(distinct_ids)

            # Evaluate against threshold
            if distinct_count >= self.config.min_distinct_objects:
                succ_2xx = sum(1 for e in sorted_group if 200 <= e.status_code < 300)
                redir_3xx = sum(1 for e in sorted_group if 300 <= e.status_code < 400)
                client_4xx = sum(1 for e in sorted_group if 400 <= e.status_code < 500)
                server_5xx = sum(1 for e in sorted_group if 500 <= e.status_code < 600)

                if self.config.require_successful_access and succ_2xx == 0:
                    continue

                is_seq = check_is_sequential(distinct_ids)

                # Base confidence & status awareness
                if succ_2xx > 0:
                    conf_score = 0.85 + (0.10 if is_seq else 0.0) + (0.04 if succ_2xx > 2 else 0.02)
                else:
                    conf_score = 0.65 + (0.10 if is_seq else 0.0)

                conf_score = min(0.98, max(0.50, round(conf_score, 2)))

                status_desc = f"{succ_2xx} successful 2xx, {client_4xx + server_5xx} failed" if (client_4xx + server_5xx) > 0 else f"{succ_2xx} successful 2xx"
                seq_desc = " Sequential access pattern detected." if is_seq else ""
                fail_note = " Note: All requests were unsuccessful (non-2xx response status)." if succ_2xx == 0 else ""
                
                exp = (
                    f"Actor '{actor_id}' accessed {distinct_count} distinct '{res_type}' objects "
                    f"through endpoint '{endpoint}' ({status_desc}).{seq_desc}{fail_note}"
                )

                ev = BolaEvidence(
                    actor_id=actor_id,
                    resource_type=res_type,
                    normalized_endpoint=endpoint,
                    accessed_object_ids=distinct_ids,
                    distinct_object_count=distinct_count,
                    is_sequential=is_seq,
                    successful_access_count=succ_2xx,
                    redirect_access_count=redir_3xx,
                    client_error_count=client_4xx,
                    server_error_count=server_5xx,
                    request_ids=[e.request_id for e in sorted_group],
                    timestamps=[e.timestamp for e in sorted_group],
                    methods=[e.method for e in sorted_group],
                    status_codes=[e.status_code for e in sorted_group],
                    confidence_score=conf_score,
                    explanation=exp
                )
                evidences.append(ev)

        # Verdict assignment
        if evidences:
            verdict = DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
            summary = f"Suspicious BOLA candidate detected: {len(evidences)} cross-object access pattern(s) identified."
        elif missing_actor_count > 0:
            verdict = DetectionVerdict.INSUFFICIENT_EVIDENCE
            summary = f"Insufficient evidence: {missing_actor_count} object access event(s) lacked non-sensitive actor identity (actor_id)."
        else:
            verdict = DetectionVerdict.NO_SUSPICIOUS_BEHAVIOR
            summary = "No suspicious BOLA/IDOR behavior detected in analyzed traffic sequence."

        return BolaDetectionResult(
            verdict=verdict,
            evidences=evidences,
            analyzed_event_count=len(events),
            explanation=summary
        )

    def analyze_traffic_logs(
        self,
        logs: List[APITrafficLog],
        headers_map: Optional[Dict[str, Dict[str, str]]] = None
    ) -> BolaDetectionResult:
        """Convenience method to analyze a list of APITrafficLog ORM objects."""
        headers_map = headers_map or {}
        events = [
            extract_from_traffic_log(log, headers=headers_map.get(log.request_id))
            for log in logs
        ]
        return self.analyze_events(events)
