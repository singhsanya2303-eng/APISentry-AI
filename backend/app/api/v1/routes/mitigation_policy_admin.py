"""Authenticated policy lifecycle administration endpoints (Gate C).

The route layer performs only: trusted-actor derivation, RBAC enforcement,
delegation to the approved Gate A lifecycle service, Gate B persistence in one
caller-owned transaction, and safe error mapping. No business rule is duplicated.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.security import require_admin, require_analyst
from app.db.session import get_db
from app.schemas.mitigation_admin import (
    ActivePolicyResponse,
    PolicyActivateRequest,
    PolicyDeactivateRequest,
    PolicyListResponse,
    PolicyProposalRequest,
    PolicyRetireRequest,
    PolicyRollbackRequest,
    PolicyValidateRequest,
)
from app.schemas.mitigation_policy_lifecycle import (
    ImmutablePolicyVersion,
    LifecycleActor,
    LifecycleErrorCode,
    LifecycleRole,
    PolicyEvaluationResult,
    PolicyLifecycleResult,
)
from app.services.mitigation_policy_lifecycle_persistence_service import (
    LifecyclePersistenceConflictError,
    LifecyclePersistenceDatabaseError,
    LifecyclePersistenceError,
    LifecyclePersistenceValidationError,
    persist_lifecycle_result,
)
from app.services.mitigation_policy_lifecycle_service import (
    MitigationPolicyLifecycleService,
)

router = APIRouter(
    prefix="/security/mitigation/policies",
    tags=["Mitigation Policy Administration"],
)
logger = logging.getLogger("apisentry.api.mitigation_policy_admin")

_ACTOR_HASH_DOMAIN = "apisentry:mitigation:jwt-actor:v1"

# One process-lifetime registry. Gate A is intentionally in-memory; Gate B rows
# are the durable projection and are lossy for lifecycle metadata.
_lifecycle_service = MitigationPolicyLifecycleService()


def get_lifecycle_service() -> MitigationPolicyLifecycleService:
    """Return the shared Gate A lifecycle registry."""
    return _lifecycle_service


def _verified_actor_hash(actor_id: str) -> str:
    digest = hashlib.sha256(
        f"{_ACTOR_HASH_DOMAIN}:{actor_id}".encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def actor_from_request(request: Request, allowed_roles: set[str]) -> LifecycleActor:
    """Derive a lifecycle actor only from verified request state."""
    user = getattr(request.state, "user", None)
    role = getattr(user, "role", None)
    if role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted for this role.",
        )
    actor_id = (
        getattr(request.state, "actor_id", None)
        or getattr(user, "actor_id", None)
        or getattr(user, "id", None)
    )
    if actor_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    lifecycle_role = (
        LifecycleRole.ADMIN if role == "admin" else LifecycleRole.ANALYST
    )
    return LifecycleActor(
        role=lifecycle_role,
        actor_hash=_verified_actor_hash(str(actor_id)),
    )


_STATUS_BY_ERROR_CODE: dict[LifecycleErrorCode, int] = {
    LifecycleErrorCode.VALIDATION_ERROR: 422,
    LifecycleErrorCode.UNSUPPORTED_ACTION: status.HTTP_400_BAD_REQUEST,
    LifecycleErrorCode.UNAUTHORIZED: status.HTTP_403_FORBIDDEN,
    LifecycleErrorCode.POLICY_NOT_FOUND: status.HTTP_404_NOT_FOUND,
    LifecycleErrorCode.VERSION_CONFLICT: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.POLICY_ALREADY_ACTIVE: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.POLICY_NOT_ACTIVE: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.POLICY_DISABLED: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.POLICY_CONFIGURATION_INVALID: 422,
    LifecycleErrorCode.POLICY_EXPIRED: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.POLICY_NOT_YET_VALID: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.INVALID_TRANSITION: status.HTTP_409_CONFLICT,
    LifecycleErrorCode.EVALUATION_FAILED: 422,
}


def _status_for_error_code(code: LifecycleErrorCode | str) -> int:
    value = code.value if isinstance(code, LifecycleErrorCode) else code
    try:
        parsed = LifecycleErrorCode(value)
    except ValueError:
        return 422
    return _STATUS_BY_ERROR_CODE.get(
        parsed, 422
    )


def raise_for_lifecycle_result(result: PolicyLifecycleResult) -> None:
    """Map a failed Gate A lifecycle result to a safe HTTP response."""
    if result.ok:
        return
    assert result.error is not None
    raise HTTPException(
        status_code=_status_for_error_code(result.error.code),
        detail=result.error.model_dump(mode="json"),
    )


def raise_for_evaluation_result(result: PolicyEvaluationResult) -> None:
    """Map a failed Gate A evaluation result to a safe HTTP response."""
    if result.ok:
        return
    assert result.error is not None
    raise HTTPException(
        status_code=_status_for_error_code(result.error.code),
        detail=result.error.model_dump(mode="json"),
    )


def _raise_for_persistence_result(error: str | None) -> None:
    code = error or "validation_error"
    raise HTTPException(
        status_code=_status_for_error_code(code),
        detail={"code": code, "source": "persistence"},
    )


def raise_for_persistence_exception(exc: LifecyclePersistenceError) -> None:
    """Map Gate B persistence failures without leaking SQL or DSNs."""
    if isinstance(exc, LifecyclePersistenceValidationError):
        raise HTTPException(
            status_code=422,
            detail={"code": "persistence_validation_error", "message": str(exc)},
        ) from None
    if isinstance(exc, LifecyclePersistenceConflictError):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "persistence_conflict"},
        ) from None
    if isinstance(exc, LifecyclePersistenceDatabaseError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error.",
        ) from None
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal server error.",
    ) from None


def _execute_and_persist(
    db: Session,
    result_factory: Any,
) -> PolicyLifecycleResult:
    """Run one lifecycle operation and persist it in one caller-owned commit."""
    try:
        result = result_factory()
        raise_for_lifecycle_result(result)
        persisted = persist_lifecycle_result(db, result)
        if not persisted.ok:
            _raise_for_persistence_result(persisted.error)
        db.commit()
        return result
    except HTTPException:
        db.rollback()
        raise
    except LifecyclePersistenceError as exc:
        db.rollback()
        raise_for_persistence_exception(exc)
    except Exception:
        db.rollback()
        logger.exception("mitigation policy lifecycle operation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error.",
        ) from None


@router.get("", response_model=PolicyListResponse)
def list_policies(
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> PolicyListResponse:
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    versions = list(service.policy_versions())
    return PolicyListResponse(
        active_version=service.active_version,
        versions=versions,
        policies=[policy for version in versions if (policy := service.get_policy(version))],
    )


@router.get("/active", response_model=ActivePolicyResponse)
def get_active_policy(
    db: Session = Depends(get_db),
    analyst_user: Any = Depends(require_analyst),
) -> ActivePolicyResponse:
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    version = service.active_version
    return ActivePolicyResponse(
        active_version=version,
        policy=service.get_policy(version) if version else None,
    )


@router.get("/{policy_version}", response_model=ImmutablePolicyVersion)
def get_policy(
    policy_version: str,
    analyst_user: Any = Depends(require_analyst),
) -> ImmutablePolicyVersion:
    policy = get_lifecycle_service().get_policy(policy_version)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy version not found.",
        )
    return policy


@router.post("", response_model=PolicyLifecycleResult, status_code=status.HTTP_201_CREATED)
def propose_policy(
    request: PolicyProposalRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.propose_policy(
            actor=actor,
            config=request.config,
            created_at=request.created_at,
            valid_from=request.valid_from,
            valid_until=request.valid_until,
            predecessor_version=request.predecessor_version,
        ),
    )


@router.post("/{policy_version}/validate", response_model=PolicyLifecycleResult)
def validate_policy(
    policy_version: str,
    request: PolicyValidateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.validate_policy(
            actor=actor,
            version=policy_version,
            at=request.at,
        ),
    )


@router.post("/{policy_version}/activate", response_model=PolicyLifecycleResult)
def activate_policy(
    policy_version: str,
    request: PolicyActivateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.activate_policy(
            actor=actor,
            version=policy_version,
            at=request.at,
            reason_code=request.reason_code,
            **request.expected_active_kwargs(),
        ),
    )


@router.post("/deactivate", response_model=PolicyLifecycleResult)
def deactivate_policy(
    request: PolicyDeactivateRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.deactivate_policy(
            actor=actor,
            version=request.version,
            at=request.at,
            reason_code=request.reason_code,
            **request.expected_active_kwargs(),
        ),
    )


@router.post("/{policy_version}/retire", response_model=PolicyLifecycleResult)
def retire_policy(
    policy_version: str,
    request: PolicyRetireRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.retire_policy(
            actor=actor,
            version=policy_version,
            at=request.at,
        ),
    )


@router.post("/{policy_version}/rollback", response_model=PolicyLifecycleResult)
def rollback_policy(
    policy_version: str,
    request: PolicyRollbackRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    admin_user: Any = Depends(require_admin),
) -> PolicyLifecycleResult:
    actor = actor_from_request(http_request, {"admin"})
    service = get_lifecycle_service()
    try:
        hydration = service.hydrate_from_persistence(db)
    except Exception:
        hydration = {"ok": False, "diverged": True, "error": "hydration_exception"}
    if not hydration.get("ok", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "mitigation_registry_inconsistent",
                "message": "Mitigation registry consistency cannot be established; mutation rejected (fail-closed).",
                "consistency_note": str(hydration.get("error") or "inconsistent"),
            },
        )
    return _execute_and_persist(
        db,
        lambda: service.rollback_policy(
            actor=actor,
            target_version=policy_version,
            at=request.at,
            **request.expected_active_kwargs(),
        ),
    )
