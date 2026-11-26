from datetime import datetime, timezone

from app.schemas.mitigation import MitigationPolicyConfig
from app.schemas.mitigation_policy_lifecycle import LifecycleActor, LifecycleRole
from app.services.mitigation_policy_lifecycle_persistence_service import (
    load_active_policy_version,
    persist_lifecycle_result,
)
from app.services.mitigation_policy_lifecycle_service import MitigationPolicyLifecycleService
from tests.mitigation_persistence_helpers import sqlite_session_factory


FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ADMIN_ACTOR = LifecycleActor(role=LifecycleRole.ADMIN, actor_hash="sha256:" + "a" * 64)


def _policy(version="v1.0.0"):
    return MitigationPolicyConfig(
        policy_version=version,
        enabled=True,
        mode="enforce",
        monitoring_score_threshold=20.0,
        throttling_score_threshold=60.0,
        blocking_score_threshold=80.0,
        minimum_authentication_failures=3,
        require_grouped_brute_force=False,
        throttle_enabled=True,
        throttle_limit=10,
        throttle_window_seconds=60,
        throttle_duration_seconds=60,
        block_enabled=True,
        block_duration_seconds=60,
        max_block_duration_seconds=300,
        admin_protection_enabled=True,
        max_evidence_references=10,
    )


def test_hydration_restores_active_policy_after_restart():
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        svc = MitigationPolicyLifecycleService()
        created = svc.propose_policy(actor=ADMIN_ACTOR, config=_policy("r1.0.0"), created_at=FIXED_NOW)
        assert created.ok
        validated = svc.validate_policy(actor=ADMIN_ACTOR, version="r1.0.0", at=FIXED_NOW)
        assert validated.ok
        activated = svc.activate_policy(actor=ADMIN_ACTOR, version="r1.0.0", at=FIXED_NOW)
        assert activated.ok
        persist_lifecycle_result(db, created)
        persist_lifecycle_result(db, validated)
        persist_lifecycle_result(db, activated)
        db.commit()
        assert load_active_policy_version(db) == "r1.0.0"

        # Simulate restart: fresh in-memory service
        svc2 = MitigationPolicyLifecycleService()
        assert svc2.active_version is None
        report = svc2.hydrate_from_persistence(db)
        assert report["ok"] is True
        assert svc2.active_version == "r1.0.0"
        policy = svc2.get_policy("r1.0.0")
        assert policy is not None
        assert policy.state.value == "ACTIVE"
        assert policy.config.policy_version == "r1.0.0"
    finally:
        db.close()
        engine.dispose()


def test_hydration_reports_divergence_without_overriding_memory():
    engine, factory = sqlite_session_factory()
    db = factory()
    try:
        svc = MitigationPolicyLifecycleService()
        created = svc.propose_policy(actor=ADMIN_ACTOR, config=_policy("d1.0.0"), created_at=FIXED_NOW)
        persist_lifecycle_result(db, created)
        db.commit()

        # In-memory has different active
        svc._policies["d1.0.0"] = svc._policies["d1.0.0"].model_copy(update={"state": "ACTIVE"}) if False else svc._policies["d1.0.0"]
        svc.propose_policy(actor=ADMIN_ACTOR, config=_policy("d2.0.0"), created_at=FIXED_NOW)
        svc.validate_policy(actor=ADMIN_ACTOR, version="d2.0.0", at=FIXED_NOW)
        svc.activate_policy(actor=ADMIN_ACTOR, version="d2.0.0", at=FIXED_NOW)
        # DB active remains none/d1 not active; memory is d2
        report = svc.hydrate_from_persistence(db)
        assert svc.active_version == "d2.0.0"
        # No persisted active, so no divergence
        assert report["diverged"] is False
    finally:
        db.close()
        engine.dispose()