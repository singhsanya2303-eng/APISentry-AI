import secrets

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def production_environments():
    return [" production ", "PRODUCTION", "Production"]


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_require_jwt_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(ENVIRONMENT=environment, JWT_SECRET_KEY="")


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_reject_development_jwt_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(
            ENVIRONMENT=environment,
            JWT_SECRET_KEY="local-development-only-jwt-secret",
        )


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_reject_predictable_long_secret(environment):
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(ENVIRONMENT=environment, JWT_SECRET_KEY="a" * 64)


@pytest.mark.parametrize("environment", production_environments())
def test_production_settings_accept_cryptographically_random_secret(environment):
    secret = secrets.token_urlsafe(32)
    configured = Settings(
        ENVIRONMENT=environment,
        JWT_SECRET_KEY=secret,
    )

    assert configured.ENVIRONMENT == "production"


@pytest.mark.parametrize("environment", production_environments())
def test_demo_auth_is_unavailable_in_production(environment):
    configured = Settings(
        ENVIRONMENT=environment,
        JWT_SECRET_KEY=secrets.token_urlsafe(32),
        APISENTRY_ENABLE_DEMO_AUTH=True,
        DEMO_PASSWORD="configured-demo-password",
    )

    assert configured.is_demo_auth_enabled is False
