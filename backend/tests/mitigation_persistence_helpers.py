"""Shared fixtures/builders for Stage 2C Phase 3 persistence tests.

Every helper stays inside isolated in-memory SQLite databases. No configured
database is contacted and no schema is created outside the test engine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any

from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.mitigation import MitigationPolicy, MitigationPolicyState
from app.schemas.mitigation import (
    MitigationAttributionStatus,
    MitigationDecision as EvaluatedDecision,
    MitigationDecisionType,
    MitigationScopeType,
)

VALID_HASH = "sha256:" + "a" * 64
OTHER_HASH = "sha256:" + "b" * 64


def opaque_uuid5(label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"apisentry-phase3:{label}"))


def unique_uuid5() -> str:
    return opaque_uuid5(uuid.uuid4().hex)


def sqlite_session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, factory


def policy_record(policy_version: str = "phase3-1.0.0", **overrides: Any) -> MitigationPolicy:
    values: dict[str, Any] = {
        "creator_hash": VALID_HASH,
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return MitigationPolicy(policy_version=policy_version, **values)


def activate_policy(session, record: MitigationPolicy) -> MitigationPolicyState:
    state = MitigationPolicyState(id=1, policy_id=record.id)
    session.add(state)
    session.flush()
    return state


def evaluated_decision(
    policy_version: str = "phase3-1.0.0", **overrides: Any
) -> EvaluatedDecision:
    issued_at = datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc)
    values: dict[str, Any] = {
        "decision": MitigationDecisionType.ALLOW,
        "scope_type": MitigationScopeType.UNATTRIBUTED,
        "scope_key_hash": None,
        "attribution_status": MitigationAttributionStatus.MISSING,
        "verified_attribution": False,
        "reason_codes": ["no_suspicious_evidence"],
        "explanation": "Advisory-only decision; no request enforcement performed.",
        "policy_version": policy_version,
        "evidence_references": [unique_uuid5()],
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(minutes=5),
        "rate_limit": None,
        "rate_limit_window_seconds": None,
        "advisory_only": True,
    }
    values.update(overrides)
    return EvaluatedDecision(**values)


def audit_kwargs(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "event_uuid": unique_uuid5(),
        "event_type": "decision_issued",
        "entity_type": "decision",
        "entity_identifier": "decision-" + uuid.uuid4().hex,
        "event_hash": VALID_HASH,
        "chain_id": "chain-" + uuid.uuid4().hex,
        "sequence_no": 1,
        "policy_id": None,
        "decision_id": None,
        "actor_hash": None,
        "actor_role": None,
        "details": {"decision_type": "allow"},
        "previous_event_hash": None,
        "created_at": datetime(2026, 2, 10, 9, 30, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return values
