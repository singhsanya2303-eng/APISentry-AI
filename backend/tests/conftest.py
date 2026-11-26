import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

# The test harness explicitly opts into the demo control-plane routers in this
# non-production process. Production gating is covered by dedicated tests that
# build fresh apps with production/default configuration.
os.environ["APISENTRY_ENABLE_DEMO_CONTROL_PLANE"] = "true"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main as app_main_module
from app.core.rate_limit import reset_auth_rate_limits
from app.core.security import (
    create_access_token,
    require_analyst_or_api_key,
    require_api_key,
)
from app.db import session as db_session_module
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.traffic import APITrafficLog  # noqa: F401
from app.models.user import User  # noqa: F401
from app.services import traffic_service

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from classifier_artifact_policy import (  # noqa: E402
    CLASSIFIER_ARTIFACT_REQUIRED_DEST,
    CLASSIFIER_ARTIFACT_REQUIRED_OPTION,
    ClassifierArtifactRequiredError,
    validate_required_classifier_artifact,
)


def pytest_addoption(parser):
    parser.addoption(
        "--require-classifier-artifact",
        action="store_true",
        default=False,
        help=(
            "Fail classifier artifact-backed tests when the frozen research "
            "bundle is absent instead of allowing the explicit skip."
        ),
    )


def pytest_collection_modifyitems(config, items):
    required = config.getoption(CLASSIFIER_ARTIFACT_REQUIRED_DEST)
    try:
        validate_required_classifier_artifact(required)
    except ClassifierArtifactRequiredError as exc:
        raise pytest.UsageError(str(exc)) from exc


def _isolated_sqlite_session_factory():
    """Create a fresh in-memory SQLite engine and matching session factory."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    return engine, factory


@pytest.fixture(scope="session", autouse=True)
def original_harness_state():
    """Snapshot state once and assert full restoration after the test session."""
    snapshot = {
        "get_db_override": app.dependency_overrides.get(get_db),
        "session_local": db_session_module.SessionLocal,
        "traffic_session_local": traffic_service.SessionLocal,
        "init_db": app_main_module.init_db,
    }
    yield snapshot
    assert app.dependency_overrides.get(get_db) is snapshot["get_db_override"]
    assert db_session_module.SessionLocal is snapshot["session_local"]
    assert traffic_service.SessionLocal is snapshot["traffic_session_local"]
    assert app_main_module.init_db is snapshot["init_db"]


@pytest.fixture(autouse=True)
def isolated_database_defaults(monkeypatch):
    """
    Route every test database path to a disposable in-memory SQLite database.

    ``dependency_overrides[get_db]`` covers route dependencies, while the two
    SessionLocal patches cover direct persistence paths such as request traffic
    logging and readiness checks. Every patch is restored by monkeypatch.
    """
    engine, factory = _isolated_sqlite_session_factory()

    previous_override = app.dependency_overrides.get(get_db)

    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(db_session_module, "SessionLocal", factory)
    monkeypatch.setattr(traffic_service, "SessionLocal", factory)

    try:
        yield factory
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override
        engine.dispose()


@pytest.fixture(autouse=True)
def block_external_init_db(monkeypatch):
    """Prevent any TestClient lifespan from running schema creation during tests."""
    mock_init_db = MagicMock()
    monkeypatch.setattr(app_main_module, "init_db", mock_init_db)
    yield mock_init_db


@pytest.fixture(autouse=True)
def override_api_key_authentication(request):
    # Keep authentication enabled in dedicated authentication tests.
    if request.node.path.name in (
        "test_authentication.py",
        "test_jwt_authentication.py",
        "test_persistent_auth.py",
    ):
        yield
        return

    auth_dependencies = (require_api_key, require_analyst_or_api_key)
    previous_overrides = {
        dependency: app.dependency_overrides.get(dependency)
        for dependency in auth_dependencies
    }
    for dependency in auth_dependencies:
        app.dependency_overrides[dependency] = lambda: None

    yield

    for dependency, previous_override in previous_overrides.items():
        if previous_override is None:
            app.dependency_overrides.pop(dependency, None)
        else:
            app.dependency_overrides[dependency] = previous_override


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    reset_auth_rate_limits()
    yield
    reset_auth_rate_limits()


@pytest.fixture
def testing_session_factory():
    """
    Provide an isolated in-memory SQLite database for tests that touch routes
    using ``get_db``. This avoids reading from or writing to the configured
    PostgreSQL database during the test run.
    """
    engine, TestingSessionLocal = _isolated_sqlite_session_factory()

    previous_override = app.dependency_overrides.get(get_db)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestingSessionLocal
    finally:
        if previous_override is None:
            app.dependency_overrides.pop(get_db, None)
        else:
            app.dependency_overrides[get_db] = previous_override
        engine.dispose()


@pytest.fixture
def test_admin_identity():
    return {
        "sub": "test-admin",
        "username": "admin@example.test",
        "user_id": 910001,
        "role": "admin",
        "is_active": True,
    }


@pytest.fixture
def test_analyst_identity():
    return {
        "sub": "test-analyst",
        "username": "analyst@example.test",
        "user_id": 910002,
        "role": "analyst",
        "is_active": True,
    }


@pytest.fixture
def test_viewer_identity():
    return {
        "sub": "test-viewer",
        "username": "viewer@example.test",
        "user_id": 910003,
        "role": "viewer",
        "is_active": True,
    }


def _identity_token(identity):
    return create_access_token(
        subject=identity["sub"],
        extra_claims={
            "username": identity["username"],
            "user_id": identity["user_id"],
            "role": identity["role"],
            "is_active": identity["is_active"],
        },
    )


@pytest.fixture
def admin_headers(test_admin_identity):
    return {"Authorization": f"Bearer {_identity_token(test_admin_identity)}"}


@pytest.fixture
def analyst_headers(test_analyst_identity):
    return {"Authorization": f"Bearer {_identity_token(test_analyst_identity)}"}


@pytest.fixture
def viewer_headers(test_viewer_identity):
    return {"Authorization": f"Bearer {_identity_token(test_viewer_identity)}"}
