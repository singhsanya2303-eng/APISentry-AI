import secrets

import pytest
from pydantic import ValidationError
from sqlalchemy.engine import make_url

from app.core.config import Settings


def production_environments():
    return [" production ", "PRODUCTION", "Production"]


def _production_kwargs(**overrides) -> dict:
    configured = {
        "ENVIRONMENT": "production",
        "JWT_SECRET_KEY": secrets.token_urlsafe(32),
        "CORS_ORIGINS": ["https://app.example.test"],
        "DATABASE_URL": "postgresql://app_user:not-a-real-secret@db.example.test:5432/app_db",
        "APISENTRY_ENABLE_PUBLIC_REGISTRATION": False,
        "_env_file": None,
    }
    configured.update(overrides)
    return configured


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_require_jwt_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(**_production_kwargs(ENVIRONMENT=environment, JWT_SECRET_KEY=""))


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_reject_development_jwt_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(
            **_production_kwargs(
                ENVIRONMENT=environment,
                JWT_SECRET_KEY="local-development-only-jwt-secret",
            )
        )


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_reject_predictable_long_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(**_production_kwargs(ENVIRONMENT=environment, JWT_SECRET_KEY="a" * 64))


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_reject_placeholder_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(
            **_production_kwargs(
                ENVIRONMENT=environment,
                JWT_SECRET_KEY="REPLACE_WITH_GENERATED_43_CHAR_BASE64URL_SECRET",
            )
        )


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_accept_cryptographically_random_secret(environment):
    configured = Settings(**_production_kwargs(ENVIRONMENT=environment))

    assert configured.ENVIRONMENT == "production"


@pytest.mark.parametrize(
    "environment",
    ["prod", "PROD", "prd", "live", "production-beta", "prod_eu"],
)
def test_production_aliases_are_rejected(environment):
    with pytest.raises(ValidationError, match="ENVIRONMENT is ambiguous"):
        Settings(**_production_kwargs(ENVIRONMENT=environment))


def test_unknown_environment_is_rejected():
    with pytest.raises(ValidationError, match="ENVIRONMENT must be one of"):
        Settings(**_production_kwargs(ENVIRONMENT="unknown"))


def test_production_forces_debug_and_schema_creation_off():
    configured = Settings(
        **_production_kwargs(DEBUG=True, AUTO_CREATE_SCHEMA=True)
    )

    assert configured.DEBUG is False
    assert configured.AUTO_CREATE_SCHEMA is False


def test_production_requires_explicit_database_target():
    kwargs = _production_kwargs()
    kwargs.pop("DATABASE_URL")

    with pytest.raises(ValidationError, match="explicit DATABASE_URL"):
        Settings(**kwargs)


def test_production_accepts_explicit_postgres_target_fields():
    configured = Settings(
        **_production_kwargs(
            DATABASE_URL=None,
            POSTGRES_SERVER="db.example.test",
            POSTGRES_PORT=5432,
            POSTGRES_USER="app_user",
            POSTGRES_PASSWORD="not-a-real-secret",
            POSTGRES_DB="app_db",
        )
    )

    assert configured.is_production
    assert configured.DATABASE_URL is None


def test_database_url_components_are_escaped():
    configured = Settings(
        POSTGRES_PASSWORD="p@ss:/?#%",
        POSTGRES_USER="app user",
        POSTGRES_DB="app/db",
        _env_file=None,
    )

    parsed = make_url(configured.get_database_url())
    assert parsed.password == "p@ss:/?#%"
    assert parsed.username == "app user"
    assert parsed.database == "app/db"


@pytest.mark.parametrize(
    "database_url",
    ["sqlite:///local.db", "postgresql://", "not-a-url", "mysql://db.example.test/app"],
)
def test_production_rejects_invalid_database_url(database_url):
    with pytest.raises(ValidationError, match="explicit DATABASE_URL"):
        Settings(**_production_kwargs(DATABASE_URL=database_url))


@pytest.mark.parametrize(
    "origin",
    ["http://app.example.test", "http://admin.example.test:8080"],
)
def test_production_rejects_non_https_non_loopback_cors_origin(origin):
    with pytest.raises(ValidationError, match="https"):
        Settings(**_production_kwargs(CORS_ORIGINS=[origin]))


def test_production_requires_at_least_one_cors_origin():
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        Settings(**_production_kwargs(CORS_ORIGINS=[]))


def test_production_rejects_placeholder_database_password():
    with pytest.raises(ValidationError, match="database credentials"):
        Settings(
            **_production_kwargs(
                DATABASE_URL="postgresql://app_user:REPLACE_WITH_DB_PASSWORD@db.example.test:5432/app_db"
            )
        )
    with pytest.raises(ValidationError, match="database credentials"):
        Settings(
            **_production_kwargs(
                DATABASE_URL=None,
                POSTGRES_SERVER="db.example.test",
                POSTGRES_PORT=5432,
                POSTGRES_USER="app_user",
                POSTGRES_PASSWORD="REPLACE_WITH_DB_PASSWORD",
                POSTGRES_DB="app_db",
            )
        )


def test_production_rejects_placeholder_api_key():
    with pytest.raises(ValidationError, match="API_KEY"):
        Settings(
            **_production_kwargs(API_KEY="REPLACE_WITH_GENERATED_SERVICE_KEY_OR_LEAVE_EMPTY")
        )


@pytest.mark.parametrize("environment", production_environments())
def test_demo_auth_is_unavailable_in_production(environment):
    configured = Settings(
        **_production_kwargs(
            ENVIRONMENT=environment,
            APISENTRY_ENABLE_DEMO_AUTH=True,
            DEMO_PASSWORD="configured-demo-password",
            APISENTRY_ENABLE_DEMO_CONTROL_PLANE=True,
        )
    )

    assert configured.is_demo_auth_enabled is False
    assert configured.is_demo_control_plane_enabled is False
