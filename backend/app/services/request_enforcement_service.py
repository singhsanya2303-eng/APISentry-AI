"""Isolated, explicitly enabled request-time enforcement runtime.

This module is the missing connection between the accepted APISentry detection,
MW1/MW2, policy lifecycle, decision and audit components, and a real FastAPI
request. It is deliberately inert unless a trusted in-process caller enables it
for an explicitly isolated loopback harness with an injected session factory.

Safety contract:
  - No import-time activation, no global middleware registration and no
    environment-variable activation.
  - Enforcement requires an exact isolated-environment confirmation, loopback
    peer/target and an ACTIVE policy already registered in the reused lifecycle.
  - Disabled mode is pure pass-through. Kill-switch mode is advisory-only: the
    accepted pipeline still produces decisions, but no request is rejected.
  - Enforcement failures fail closed with HTTP 503; they never become ALLOW.
  - Audit details contain only opaque references, allowlisted scalars and safe
    codes. No header, credential, secret or raw body is persisted here.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import threading
import uuid
from typing import Any, Callable, Deque

from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.models.mitigation import (
    MitigationAuditEntityType,
    MitigationAuditEvent,
    MitigationAuditEventType,
    MitigationDecision as MitigationDecisionRow,
    MitigationPolicy as MitigationPolicyRow,
)
from app.models.traffic import APITrafficLog
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecisionType,
    MitigationRequestContext,
)
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, PolicyLifecycleState
from app.services.bot_detection_service import (
    BotAnalysisResult,
    BotDetectionResponse,
    BotScoringConfig,
    analyze_traffic_for_bot_detection,
)
from app.services.mitigation_audit_persistence_service import persist_audit_event
from app.services.mitigation_policy_lifecycle_persistence_service import (
    persist_evaluation_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)
from app.services.mw4_runtime_orchestration_service import orchestrate_mw4_runtime
from app.utils.middleware import sanitize_query_params

logger = logging.getLogger("apisentry.request_enforcement")

ISOLATED_HARNESS_ENVIRONMENT = "isolated_test_harness"
_REQUEST_REF_NAMESPACE = uuid.UUID("1f0c9a8e-6b4d-5a2f-8c31-9d7e2b5a4f60")
_AUDIT_NAMESPACE = uuid.UUID("6b2d4f81-3c5a-5e7b-9d04-8a1f6c2b9e30")
_REMOVAL_AUDIT_LOOKBACK_MULTIPLIER = 4


class EnforcementGuardError(RuntimeError):
    """An explicit safety guard prevented runtime activation."""


class EnforcementFailure(RuntimeError):
    """An enforcement dependency failed while enforcement was active."""


@dataclass
class _RuntimeState:
    configured: bool = False
    environment: str | None = None
    client_host: str | None = None
    target_host: str | None = None
    session_factory: Callable[[], Session] | None = None
    lifecycle: MitigationPolicyLifecycleService | None = None
    actor: LifecycleActor | None = None
    policy_version: str | None = None
    active_enforcement_version: str | None = None
    enforcement_enabled: bool = False
    kill_switch_active: bool = False
    detector: Callable[..., BotDetectionResponse] | None = None
    audit_sink: Callable[..., Any] | None = None
    clock: Callable[[], datetime] | None = None
    scoring_config: BotScoringConfig | None = None
    max_requests: int = 100
    max_duration_seconds: int = 300
    activated_at: datetime | None = None
    request_count: int = 0
    throttle_buckets: dict[str, Deque[float]] = field(default_factory=dict)


def _default_audit_sink(session: Session, **kwargs: Any) -> Any:
    return persist_audit_event(session, **kwargs)


def _require_loopback(host: str | None, field_name: str) -> str:
    """Accept only loopback literals for this isolated harness."""
    if not isinstance(host, str) or not host.strip():
        raise EnforcementGuardError(f"{field_name} is required")
    clean = host.strip()
    if clean.lower() in {"localhost", "ip6-localhost"}:
        return clean
    try:
        address = ipaddress.ip_address(clean)
    except ValueError as exc:
        raise EnforcementGuardError(f"{field_name} must be a loopback host") from exc
    if not address.is_loopback:
        raise EnforcementGuardError(f"{field_name} must be a loopback host")
    return clean


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _select_detection_result(
    response: BotDetectionResponse, client_host: str, actor_hash: str
) -> BotAnalysisResult:
    results = list(response.results or [])
    exact = [
        result
        for result in results
        if result.client_ip == client_host and result.actor_id == actor_hash
    ]
    if len(exact) == 1:
        return exact[0]
    raise EnforcementFailure("No unambiguous detection result for the synthetic subject")


def _select_mw4_runtime_result(
    response: BotDetectionResponse,
    detection_result: BotAnalysisResult,
    runtime_results: list[Any],
) -> Any:
    """Select the MW4 composition belonging to the unambiguous detection result."""

    results = list(response.results or [])
    index = next((i for i, item in enumerate(results) if item is detection_result), None)
    if index is None:
        matches = [
            i
            for i, item in enumerate(results)
            if item.client_ip == detection_result.client_ip
            and item.actor_id == detection_result.actor_id
            and item.bot_risk_score == detection_result.bot_risk_score
        ]
        index = matches[0] if len(matches) == 1 else None
    if index is None or index >= len(runtime_results):
        raise EnforcementFailure("MW4 runtime output could not be matched to the subject")
    selected = runtime_results[index]
    if getattr(selected, "result_index", None) != index:
        raise EnforcementFailure("MW4 runtime output index is inconsistent")
    return selected


def _risk_audit_fields(risk_assessment: Any, advanced_envelope: Any) -> dict[str, Any]:
    """Extract bounded, non-sensitive MW1/MW2 scalars for audit attribution."""

    coverage = getattr(risk_assessment, "coverage", None)
    severity = getattr(risk_assessment, "severity", None)
    signals = list(getattr(advanced_envelope, "signals", []) or [])
    high_severity = sum(
        1
        for signal in signals
        if str(getattr(getattr(signal, "severity", None), "value", getattr(signal, "severity", "")))
        in {"HIGH", "CRITICAL"}
    )
    return {
        "risk_score": float(getattr(risk_assessment, "risk_score", 0.0)),
        "risk_severity": str(getattr(severity, "value", severity or "unknown")),
        "risk_coverage_ratio": float(getattr(coverage, "coverage_ratio", 0.0)),
        "mw1_status": "assessed",
        "mw2_signal_count": len(signals),
        "mw2_high_severity_count": high_severity,
    }


class IsolatedEnforcementRuntime:
    """In-process enforcement state machine for an isolated FastAPI harness."""

    def __init__(self) -> None:
        self._state = _RuntimeState()
        self._lock = threading.Lock()

    def enable(
        self,
        *,
        environment: str,
        client_host: str,
        target_host: str,
        session_factory: Callable[[], Session],
        lifecycle: MitigationPolicyLifecycleService,
        actor: LifecycleActor,
        policy_version: str,
        isolated_environment_confirmation: bool = False,
        detector: Callable[..., BotDetectionResponse] | None = None,
        audit_sink: Callable[..., Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        scoring_config: BotScoringConfig | None = None,
        max_requests: int = 100,
        max_duration_seconds: int = 300,
    ) -> dict[str, Any]:
        """Enable enforcement only for a confirmed isolated loopback harness."""
        if isolated_environment_confirmation is not True:
            raise EnforcementGuardError(
                "Explicit isolated-environment confirmation is required"
            )
        if environment != ISOLATED_HARNESS_ENVIRONMENT:
            raise EnforcementGuardError("Unsupported enforcement environment")
        clean_client = _require_loopback(client_host, "client_host")
        clean_target = _require_loopback(target_host, "target_host")
        if lifecycle.active_version != policy_version:
            raise EnforcementGuardError("Policy version is not the lifecycle ACTIVE version")
        policy = lifecycle.get_policy(policy_version)
        if policy is None or policy.state is not PolicyLifecycleState.ACTIVE:
            raise EnforcementGuardError("Active policy snapshot is unavailable")
        if not isinstance(actor, LifecycleActor) or actor.actor_hash is None:
            raise EnforcementGuardError("A pre-hashed lifecycle actor is required")

        now = (clock or _now)()
        try:
            with session_factory() as session:
                report = lifecycle.hydrate_from_persistence(session)
                recovered_buckets = self._restore_throttle_buckets(
                    session, now=now, max_requests=max_requests
                )
        except Exception as exc:
            raise EnforcementGuardError("Policy hydration could not be verified") from exc
        if report.get("diverged") is True:
            raise EnforcementGuardError("Policy hydration diverged; enforcement refused")
        report_error = report.get("error")
        if report_error not in (None, "persistence_store_unavailable"):
            raise EnforcementGuardError("Policy hydration failed; enforcement refused")

        with self._lock:
            self._state.configured = True
            self._state.environment = environment
            self._state.client_host = clean_client
            self._state.target_host = clean_target
            self._state.session_factory = session_factory
            self._state.lifecycle = lifecycle
            self._state.actor = actor
            self._state.policy_version = policy_version
            self._state.active_enforcement_version = policy_version
            self._state.enforcement_enabled = True
            self._state.kill_switch_active = False
            self._state.detector = detector or analyze_traffic_for_bot_detection
            self._state.audit_sink = audit_sink or _default_audit_sink
            self._state.clock = clock or _now
            self._state.scoring_config = scoring_config or BotScoringConfig()
            self._state.max_requests = max(1, max_requests)
            self._state.max_duration_seconds = max(1, max_duration_seconds)
            self._state.activated_at = now
            self._state.request_count = 0
            self._state.throttle_buckets = recovered_buckets
        return self.status()

    def kill_switch(self) -> dict[str, Any]:
        """Stop enforcement immediately and return to advisory-only mode."""
        with self._lock:
            previous_version = self._state.active_enforcement_version
            self._state.enforcement_enabled = False
            self._state.kill_switch_active = True
            self._state.active_enforcement_version = None
            self._state.throttle_buckets.clear()
            state = self._snapshot_locked()
        if self._state.configured and previous_version is not None:
            self._record_removal_audit(previous_version, reason="kill_switch")
        return state

    def disable(self) -> dict[str, Any]:
        """Fully disable this isolated runtime."""
        with self._lock:
            self._state.configured = False
            self._state.enforcement_enabled = False
            self._state.kill_switch_active = False
            self._state.active_enforcement_version = None
            self._state.throttle_buckets.clear()
            return self._snapshot_locked()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, Any]:
        state = self._state
        if not state.configured:
            mode = "disabled"
        elif state.enforcement_enabled:
            mode = "enforcing"
        else:
            mode = "advisory"
        return {
            "mode": mode,
            "environment": state.environment,
            "client_host": state.client_host,
            "target_host": state.target_host,
            "policy_version": state.policy_version,
            "active_enforcement_version": state.active_enforcement_version,
            "enforcement_enabled": state.enforcement_enabled,
            "kill_switch_active": state.kill_switch_active,
            "request_count": state.request_count,
            "max_requests": state.max_requests,
            "throttle_buckets": len(state.throttle_buckets),
        }

    async def process(self, request: Request, call_next: Callable[..., Any]) -> Response:
        """Run the accepted pipeline and apply the resulting action."""
        status_snapshot = self.status()
        if status_snapshot["mode"] == "disabled":
            return await call_next(request)

        state = self._state
        try:
            peer = _require_loopback(
                request.client.host if request.client is not None else None,
                "request.client.host",
            )
            target = _require_loopback(request.url.hostname, "request.url.hostname")
            if peer != state.client_host or target != state.target_host:
                raise EnforcementFailure("Request is outside the enabled isolated harness")
        except (EnforcementGuardError, EnforcementFailure) as exc:
            return self._fail_closed(request, str(exc))

        now = state.clock() if state.clock is not None else _now()
        request_ref = str(
            uuid.uuid5(
                _REQUEST_REF_NAMESPACE,
                _canonical_json(
                    {
                        "client": peer,
                        "method": request.method,
                        "path": request.url.path,
                        "at": now.isoformat(),
                        "nonce": uuid.uuid4().hex,
                    }
                ),
            )
        )
        enforcing = self._claim_request(now)
        if enforcing is None:
            return self._fail_closed(request, "Enforcement request limit or duration exceeded")

        session: Session | None = None
        traffic_row: APITrafficLog | None = None
        started = now.timestamp()
        try:
            assert state.session_factory is not None
            assert state.lifecycle is not None
            assert state.actor is not None
            assert state.actor.actor_hash is not None
            assert state.audit_sink is not None

            session = state.session_factory()
            actor_hash = state.actor.actor_hash
            traffic_row = self._record_traffic(session, request, peer, actor_hash, request_ref, now)

            detection_response = state.detector(
                client_ip=peer,
                db=session,
                max_records=1000,
                scoring_config=state.scoring_config,
            )
            if not isinstance(detection_response, BotDetectionResponse):
                raise EnforcementFailure("Detector returned an invalid response")
            detection_result = _select_detection_result(
                detection_response, peer, actor_hash
            )

            runtime_results, _timings = orchestrate_mw4_runtime(detection_response)
            mw4_result = _select_mw4_runtime_result(
                detection_response, detection_result, runtime_results
            )
            if (
                getattr(mw4_result, "mw1_status", None) != "assessed"
                or getattr(mw4_result, "mw1_unified_assessment", None) is None
            ):
                raise EnforcementFailure("MW1 assessment is unavailable for enforcement")
            risk_assessment = mw4_result.mw1_unified_assessment
            advanced_envelope = mw4_result.mw2_advanced_detection
            risk_fields = _risk_audit_fields(risk_assessment, advanced_envelope)

            context = MitigationRequestContext(
                evaluated_at=now,
                route_class="isolated_synthetic",
                is_control_plane=False,
                is_admin=False,
                attribution_status=MitigationAttributionStatus.VERIFIED_USER,
                actor_key_hash=actor_hash,
                detection_available=True,
                evidence_complete=not bool(detection_response.limits.truncated),
            )
            evaluation = state.lifecycle.evaluate_policy(
                actor=state.actor,
                version=state.policy_version,
                at=now,
                detection_result=detection_result,
                context=context,
                risk_assessment=risk_assessment,
                advanced_envelope=advanced_envelope,
                dry_run=not enforcing,
                idempotency_token=request_ref,
            )
            if not evaluation.ok or evaluation.decision is None:
                raise EnforcementFailure("Active policy evaluation failed")

            lifecycle_decision = evaluation.decision
            decision = lifecycle_decision.decision
            persistence = persist_evaluation_result(session, evaluation)
            if not persistence.ok:
                raise EnforcementFailure("Decision persistence failed")

            policy_row = (
                session.query(MitigationPolicyRow)
                .filter(MitigationPolicyRow.policy_version == state.policy_version)
                .first()
            )
            decision_row = (
                session.query(MitigationDecisionRow)
                .filter(
                    MitigationDecisionRow.decision_uuid
                    == lifecycle_decision.decision_ref
                )
                .first()
            )
            if policy_row is None or decision_row is None:
                raise EnforcementFailure("Persisted decision could not be resolved")

            selected = decision.decision
            outcome = "allowed"
            headers = {
                "X-Enforcement-Action": selected.value,
                "X-Enforcement-Outcome": "pending",
                "X-Request-Ref": request_ref,
            }
            response: Response
            if selected is MitigationDecisionType.BLOCK:
                if not enforcing:
                    outcome = "advisory_allowed"
                    response = await call_next(request)
                else:
                    outcome = "blocked"
                    response = JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Request blocked by active isolated mitigation policy",
                            "request_ref": request_ref,
                            "decision_ref": lifecycle_decision.decision_ref,
                        },
                        headers=headers,
                    )
            elif selected is MitigationDecisionType.THROTTLE:
                limit = decision.rate_limit or 1
                window = decision.rate_limit_window_seconds or 60
                throttle_key = f"{decision.scope_key_hash or request_ref}|{limit}|{window}"
                permitted, retry_after = self._throttle_check(
                    throttle_key,
                    limit=limit,
                    window_seconds=window,
                    now=now,
                    enforce=enforcing,
                )
                if permitted:
                    outcome = "throttle_permitted" if enforcing else "advisory_allowed"
                    response = await call_next(request)
                else:
                    outcome = "throttled"
                    response = JSONResponse(
                        status_code=429,
                        content={
                            "detail": "Request rate limit enforced by isolated mitigation policy",
                            "request_ref": request_ref,
                            "decision_ref": lifecycle_decision.decision_ref,
                        },
                        headers={**headers, "Retry-After": str(retry_after)},
                    )
            else:
                outcome = "allowed" if enforcing else "advisory_allowed"
                response = await call_next(request)

            response.headers["X-Enforcement-Outcome"] = outcome
            self._record_enforcement_audit(
                session=session,
                sink=state.audit_sink,
                actor_hash=actor_hash,
                policy_id=policy_row.id,
                decision_id=decision_row.id,
                policy_version=state.policy_version,
                request_ref=request_ref,
                risk_assessment_ref=lifecycle_decision.risk_assessment_ref or "unavailable",
                decision_ref=lifecycle_decision.decision_ref,
                selected_action=selected.value,
                outcome=outcome,
                advisory_only=not enforcing,
                at=now,
                risk_fields=risk_fields,
            )
            status_code = getattr(response, "status_code", 0)
            traffic_row.status_code = int(status_code)
            traffic_row.response_time_ms = max(
                0.0, (state.clock() if state.clock is not None else _now()).timestamp() - started
            )
            session.commit()
            return response
        except Exception as exc:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    logger.warning("Enforcement rollback failed", exc_info=True)
            logger.error("Request-time enforcement failed closed (%s)", type(exc).__name__)
            return self._fail_closed(request, "Enforcement dependency unavailable")
        finally:
            if session is not None:
                session.close()

    def _restore_throttle_buckets(
        self,
        session: Session,
        *,
        now: datetime,
        max_requests: int,
    ) -> dict[str, Deque[float]]:
        """Rebuild in-window throttle buckets from persisted enforcement audits."""

        buckets: dict[str, Deque[float]] = {}
        try:
            audit_rows = (
                session.query(MitigationAuditEvent)
                .filter(
                    MitigationAuditEvent.event_type
                    == MitigationAuditEventType.ENFORCEMENT_APPLIED_RESERVED
                )
                .order_by(MitigationAuditEvent.created_at.desc())
                .limit(max(1, max_requests) * _REMOVAL_AUDIT_LOOKBACK_MULTIPLIER)
                .all()
            )
            if not audit_rows:
                return buckets
            refs = {
                str((row.details or {}).get("decision_ref"))
                for row in audit_rows
                if isinstance(row.details, dict) and (row.details or {}).get("decision_ref")
            }
            decisions = {
                row.decision_uuid: row
                for row in session.query(MitigationDecisionRow)
                .filter(MitigationDecisionRow.decision_uuid.in_(refs))
                .all()
            } if refs else {}

            now_start = int(now.timestamp())
            for audit in reversed(audit_rows):
                details = dict(audit.details or {})
                if details.get("selected_action") != "throttle":
                    continue
                if details.get("enforcement_outcome") != "throttle_permitted":
                    continue
                raw_at = details.get("enforced_at")
                if not isinstance(raw_at, str):
                    continue
                try:
                    occurred_at = datetime.fromisoformat(raw_at)
                except ValueError:
                    continue
                if occurred_at.tzinfo is None:
                    occurred_at = occurred_at.replace(tzinfo=timezone.utc)
                decision = decisions.get(str(details.get("decision_ref")))
                window = int(getattr(decision, "rate_limit_window_seconds", 0) or 60)
                limit = int(getattr(decision, "rate_limit", 0) or 1)
                scope = getattr(decision, "scope_key_hash", None) or details.get("request_ref")
                if not isinstance(scope, str) or not scope:
                    continue
                key = f"{scope}|{limit}|{window}"
                window_start = now_start // window * window
                timestamp = occurred_at.timestamp()
                if timestamp >= window_start:
                    buckets.setdefault(key, deque()).append(timestamp)
        except Exception:
            logger.warning("Throttle bucket recovery skipped", exc_info=True)
            return {}
        return buckets

    def _claim_request(self, now: datetime) -> bool | None:
        """Return enforcement mode; bounded limits fall back to advisory only."""
        transition_version: str | None = None
        with self._lock:
            state = self._state
            if not state.enforcement_enabled:
                return False
            state.request_count += 1
            elapsed = (now - state.activated_at).total_seconds() if state.activated_at else 0.0
            if (
                state.request_count > state.max_requests
                or elapsed > state.max_duration_seconds
            ):
                transition_version = state.active_enforcement_version
                state.enforcement_enabled = False
                state.kill_switch_active = True
                state.active_enforcement_version = None
                state.throttle_buckets.clear()
        if transition_version is not None:
            self._record_removal_audit(transition_version, reason="bounded_limit")
            return False
        return True

    def _throttle_check(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: datetime,
        enforce: bool,
    ) -> tuple[bool, int]:
        if not enforce:
            return True, 0
        now_ts = now.timestamp()
        window_start = int(now_ts) // window_seconds * window_seconds
        retry_after = max(1, window_start + window_seconds - int(now_ts))
        with self._lock:
            bucket = self._state.throttle_buckets.setdefault(key, deque())
            while bucket and bucket[0] < window_start:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, retry_after
            bucket.append(now_ts)
            return True, 0

    def _record_traffic(
        self,
        session: Session,
        request: Request,
        client_host: str,
        actor_hash: str,
        request_ref: str,
        now: datetime,
    ) -> APITrafficLog:
        row = APITrafficLog(
            request_id=request_ref,
            timestamp=now,
            method=request.method,
            path=request.url.path,
            query_params=sanitize_query_params(dict(request.query_params)),
            client_ip=client_host,
            user_agent=request.headers.get("user-agent", "")[:500],
            status_code=0,
            response_time_ms=0.0,
            actor_id=actor_hash,
        )
        session.add(row)
        session.flush()
        return row

    def _record_enforcement_audit(
        self,
        *,
        session: Session,
        sink: Callable[..., Any],
        actor_hash: str,
        policy_id: int,
        decision_id: int,
        policy_version: str,
        request_ref: str,
        risk_assessment_ref: str,
        decision_ref: str,
        selected_action: str,
        outcome: str,
        advisory_only: bool,
        at: datetime,
        risk_fields: dict[str, Any] | None = None,
    ) -> Any:
        risk_fields = dict(risk_fields or {})
        content = {
            "domain": "apisentry.request_enforcement.audit.v1",
            "request_ref": request_ref,
            "risk_assessment_ref": risk_assessment_ref,
            "decision_ref": decision_ref,
            "policy_version": policy_version,
            "selected_action": selected_action,
            "enforcement_outcome": outcome,
            "enforced_at": at.isoformat(),
            "advisory_only": advisory_only,
            **risk_fields,
        }
        canonical = _canonical_json(content)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        details = {
            "policy_version": policy_version,
            "decision_type": selected_action,
            "reason_code": "request_enforcement_applied",
            "scope_type": "verified_user",
            "attribution_status": "verified_user",
            "request_ref": request_ref,
            "risk_assessment_ref": risk_assessment_ref,
            "decision_ref": decision_ref,
            "selected_action": selected_action,
            "enforcement_outcome": outcome,
            "enforced_at": at.isoformat(),
            "advisory_only": advisory_only,
            **risk_fields,
        }
        return sink(
            session,
            event_uuid=str(uuid.uuid5(_AUDIT_NAMESPACE, canonical)),
            event_type=MitigationAuditEventType.ENFORCEMENT_APPLIED_RESERVED,
            entity_type=MitigationAuditEntityType.DECISION,
            entity_identifier=request_ref,
            policy_id=policy_id,
            decision_id=decision_id,
            actor_hash=actor_hash,
            actor_role="admin",
            details=details,
            event_hash=f"sha256:{digest}",
            chain_id=f"enforcement-{request_ref}",
            sequence_no=1,
            previous_event_hash=None,
            created_at=at,
        )

    def _record_removal_audit(
        self, policy_version: str, *, reason: str = "kill_switch"
    ) -> None:
        """Record a kill switch or bounded-limit advisory-only transition."""
        state = self._state
        if state.session_factory is None or state.audit_sink is None:
            return
        at = state.clock() if state.clock is not None else _now()
        content = {
            "domain": "apisentry.request_enforcement.audit.v1",
            "event": reason,
            "policy_version": policy_version,
            "at": at.isoformat(),
        }
        canonical = _canonical_json(content)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        session: Session | None = None
        try:
            session = state.session_factory()
            policy_row = (
                session.query(MitigationPolicyRow)
                .filter(MitigationPolicyRow.policy_version == policy_version)
                .first()
            )
            state.audit_sink(
                session,
                event_uuid=str(uuid.uuid5(_AUDIT_NAMESPACE, canonical)),
                event_type=MitigationAuditEventType.ENFORCEMENT_REMOVED_RESERVED,
                entity_type=MitigationAuditEntityType.POLICY,
                entity_identifier=f"{reason}-{policy_version}"[:64],
                policy_id=policy_row.id if policy_row is not None else None,
                decision_id=None,
                actor_hash=state.actor.actor_hash if state.actor is not None else None,
                actor_role="admin",
                details={
                    "policy_version": policy_version,
                    "decision_type": reason,
                    "selected_action": reason,
                    "enforcement_outcome": "advisory_only",
                    "enforced_at": at.isoformat(),
                    "advisory_only": True,
                },
                event_hash=f"sha256:{digest}",
                chain_id=f"enforcement-removed-{reason}-{policy_version}",
                sequence_no=1,
                previous_event_hash=None,
                created_at=at,
            )
            session.commit()
        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            logger.warning("Kill-switch audit could not be persisted", exc_info=True)
        finally:
            if session is not None:
                session.close()

    def _fail_closed(self, request: Request, reason: str) -> JSONResponse:
        """Return a fixed 503 and never invoke the protected downstream handler."""
        del reason  # Fixed client text avoids leaking dependency internals.
        return JSONResponse(
            status_code=503,
            content={"detail": "Enforcement dependency unavailable; request not allowed"},
            headers={"X-Enforcement-Outcome": "fail_closed"},
        )


class RequestEnforcementMiddleware(BaseHTTPMiddleware):
    """Starlette middleware wrapper around the isolated runtime."""

    def __init__(self, app: Any, runtime: IsolatedEnforcementRuntime) -> None:
        super().__init__(app)
        self.runtime = runtime

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        return await self.runtime.process(request, call_next)


def _now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "ISOLATED_HARNESS_ENVIRONMENT",
    "EnforcementFailure",
    "EnforcementGuardError",
    "IsolatedEnforcementRuntime",
    "RequestEnforcementMiddleware",
]
