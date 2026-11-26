"""Proofs for the dedicated isolated pytest harness.

These tests never use the configured database. They verify that the shared
fixtures route database access to disposable in-memory SQLite, intercept
traffic-log persistence, and neutralize lifespan DDL during tests.
"""

from fastapi.testclient import TestClient

from app import main as app_main_module
from app.db import session as db_session_module
from app.db.session import get_db
from app.main import app
from app.models.traffic import APITrafficLog
from app.services import traffic_service


def test_get_db_override_uses_in_memory_sqlite(isolated_database_defaults):
    db = isolated_database_defaults()
    try:
        bind = db.get_bind()
        assert bind.url.get_backend_name() == "sqlite"
        assert bind.url.database == ":memory:"
    finally:
        db.close()


def test_direct_session_local_is_patched_to_in_memory_sqlite(isolated_database_defaults):
    assert db_session_module.SessionLocal is isolated_database_defaults
    assert traffic_service.SessionLocal is isolated_database_defaults


def test_middleware_persistence_lands_in_in_memory_database(isolated_database_defaults):
    request_id = "isolated-harness-proof-001"

    success = traffic_service.save_traffic_log(
        request_id=request_id,
        method="GET",
        path="/health",
        query_params={},
        client_ip="127.0.0.1",
        user_agent="pytest-isolated-harness",
        status_code=200,
        response_time_ms=1.0,
    )
    assert success is True

    db = isolated_database_defaults()
    try:
        row = db.query(APITrafficLog).filter_by(request_id=request_id).one()
        assert row.path == "/health"
    finally:
        db.close()


def test_lifespan_uses_mocked_init_db_and_never_runs_real_ddl(
    block_external_init_db,
    original_harness_state,
):
    assert app_main_module.init_db is block_external_init_db
    assert app_main_module.init_db is not original_harness_state["init_db"]

    with TestClient(app):
        pass

    block_external_init_db.assert_called_once()


def test_route_dependency_override_is_registered(original_harness_state):
    assert get_db in app.dependency_overrides
    assert app.dependency_overrides[get_db] is not original_harness_state["get_db_override"]
