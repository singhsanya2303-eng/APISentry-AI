"""Authenticated advisory-only mitigation dry-run endpoint (Gate C).

The endpoint hydrates the shared lifecycle registry read-only before evaluating
so an inconsistent registry fails closed with the documented 503 response. It
performs no writes; every returned decision remains advisory-only by schema and
by service invariant.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.v1.routes.mitigation_policy_admin import (
    actor_from_request,
    get_lifecycle_service,
    raise_for_evaluation_result,
)
from app.core.security import require_analyst
from app.db.session import get_db
from app.schemas.mitigation_admin import DryRunEvaluationRequest
from app.schemas.mitigation_policy_lifecycle import PolicyEvaluationResult

router = APIRouter(prefix="/security/mitigation", tags=["Mitigation Dry Run"])


@router.post("/dry-run", response_model=PolicyEvaluationResult)
def evaluate_dry_run(
    request: DryRunEvaluationRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> PolicyEvaluationResult:
    """Evaluate advisory inputs without writing policies, decisions, or traffic."""
    actor = actor_from_request(http_request, {"admin", "analyst"})
    lifecycle = get_lifecycle_service()
    try:
        hydration = lifecycle.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; policy evaluation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    result = lifecycle.evaluate_policy(
        actor=actor,
        version=request.version,
        at=request.at,
        detection_result=request.detection_result,
        context=request.context,
        risk_assessment=request.risk_assessment,
        advanced_envelope=request.advanced_envelope,
        dry_run=request.dry_run,
        idempotency_token=request.idempotency_token,
    )
    raise_for_evaluation_result(result)
    return result
