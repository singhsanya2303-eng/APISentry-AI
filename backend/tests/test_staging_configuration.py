"""Repository-side staging configuration readiness checks.

These tests inspect templates and source-level configuration only. They do not
read local .env files, contact databases, start servers, or deploy artifacts.
"""

from __future__ import annotations

from pathlib import Path
import importlib.util
import re
import secrets
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from starlette.middleware.cors import CORSMiddleware

from app.core.config import Settings, settings
from app.main import app, create_app


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_staging_templates_exist_without_secret_values() -> None:
    backend_template = (REPO_ROOT / "backend" / ".env.staging.example").read_text(
        encoding="utf-8"
    )
    frontend_template = (REPO_ROOT / "frontend" / ".env.staging.example").read_text(
        encoding="utf-8"
    )

    for key in (
        "ENVIRONMENT=production",
        "DEBUG=false",
        "JWT_SECRET_KEY=REPLACE_WITH_",
        "API_KEY=REPLACE_WITH_",
        "CORS_ORIGINS=https://",
        "AUTO_CREATE_SCHEMA=false",
        "APISENTRY_ENABLE_PUBLIC_REGISTRATION=false",
        "APISENTRY_ENABLE_DEMO_AUTH=false",
        "APISENTRY_ENABLE_DEMO_CONTROL_PLANE=false",
        "POSTGRES_PASSWORD=REPLACE_WITH_",
    ):
        assert key in backend_template
    assert "VITE_API_BASE_URL=https://" in frontend_template
    assert "REPLACE_WITH_" in backend_template
    assert "postgresql://" not in backend_template
    assert "127.0.0.1:8000" not in frontend_template
    assert "localhost:8000" not in frontend_template


def test_staging_documentation_covers_required_gates() -> None:
    staging = (REPO_ROOT / "docs" / "STAGING_PREPARATION.md").read_text(encoding="utf-8")
    database = (REPO_ROOT / "docs" / "STAGING_DATABASE_CHECKLIST.md").read_text(
        encoding="utf-8"
    )
    modules = (REPO_ROOT / "docs" / "DEMO_MODULE_MATRIX.md").read_text(encoding="utf-8")

    for required in (
        "ENVIRONMENT",
        "JWT_SECRET_KEY",
        "CORS_ORIGINS",
        "DATABASE_URL",
        "--workers 1",
        "/health",
        "/ready",
        "VITE_API_BASE_URL",
        "frontend/dist",
    ):
        assert required in staging
    for required in (
        "Fresh database",
        "Backup",
        "Migration",
        "JWT revocation",
        "Rollback",
    ):
        assert required in database
    for required in (
        "Deterministic risk",
        "Token usage",
        "Clustering",
        "Stacked autoencoder",
        "HTTP payload",
        "CSIC",
    ):
        assert required in modules


def test_development_cors_allows_default_vite_port() -> None:
    assert not Settings(_env_file=None).is_production
    local_app = create_app()
    cors = next(
        item for item in local_app.user_middleware if item.cls is CORSMiddleware
    )
    # Starlette exposes middleware options as `.options` in older releases and
    # `.kwargs` in newer ones; accept either without pinning versions.
    middleware_options = getattr(cors, "options", None)
    if middleware_options is None:
        middleware_options = cors.kwargs
    origins = set(middleware_options["allow_origins"])
    assert "http://127.0.0.1:5173" in origins
    assert "http://localhost:5173" in origins


def test_registration_defaults_to_disabled_and_production_requires_explicit_false() -> None:
    assert Settings(_env_file=None).is_public_registration_enabled is False

    production_kwargs = {
        "ENVIRONMENT": "production",
        "JWT_SECRET_KEY": secrets.token_urlsafe(32),
        "CORS_ORIGINS": ["https://app.example.test"],
        "DATABASE_URL": (
            "postgresql://app_user:generated-db-secret@db.example.test:5432/app_db"
        ),
        "APISENTRY_ENABLE_PUBLIC_REGISTRATION": False,
        "_env_file": None,
    }
    configured = Settings(**production_kwargs)
    assert configured.is_public_registration_enabled is False

    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="PUBLIC_REGISTRATION"):
        Settings(**{**production_kwargs, "APISENTRY_ENABLE_PUBLIC_REGISTRATION": True})

    omitted = dict(production_kwargs)
    omitted.pop("APISENTRY_ENABLE_PUBLIC_REGISTRATION")
    with pytest.raises(ValidationError, match="PUBLIC_REGISTRATION"):
        Settings(**omitted)


def test_health_and_readiness_routes_are_registered() -> None:
    # Starlette's included routers are version-specific objects; OpenAPI paths
    # are the stable public contract for these two routes.
    paths = set(app.openapi()["paths"])
    assert "/health" in paths
    assert "/ready" in paths


def _load_provision_admin_module():
    script_path = REPO_ROOT / "backend" / "scripts" / "provision_admin.py"
    spec = importlib.util.spec_from_file_location(
        "provision_admin_under_test", script_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, script_path.read_text(encoding="utf-8")


def test_provision_admin_refuses_production_without_confirmation(
    monkeypatch, capsys
) -> None:
    module, _source = _load_provision_admin_module()
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provision_admin.py",
            "--email",
            "owner@example.test",
            "--username",
            "temp-owner",
        ],
    )
    monkeypatch.setattr(
        module,
        "_owner_password",
        MagicMock(side_effect=AssertionError("password prompt must not run")),
    )
    monkeypatch.setattr(
        module,
        "SessionLocal",
        MagicMock(side_effect=AssertionError("database must not open")),
    )

    with pytest.raises(SystemExit, match="confirm-production"):
        module.main()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_provision_admin_never_prints_or_hardcodes_passwords(
    monkeypatch, capsys
) -> None:
    module, source = _load_provision_admin_module()

    assert 'password = os.environ.get("APISENTRY_NEW_ADMIN_PASSWORD", "")' in source
    assert 'password = getpass.getpass("New administrator password: ")' in source
    assert 'password_hash = hash_password(password_hash_input)' in source
    assert (
        'print(f"Provisioned administrator id={user.id} username={user.username}")'
        in source
    )
    assert not re.search(r"print\([^)]*\bpassword\b", source, re.IGNORECASE)
    assert not re.search(r"\bpassword\s*=\s*[\"'][^\"']+[\"']", source, re.IGNORECASE)

    generated_password = secrets.token_urlsafe(24)
    monkeypatch.setenv("APISENTRY_NEW_ADMIN_PASSWORD", generated_password)
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provision_admin.py",
            "--email",
            "owner@example.test",
            "--username",
            "temp-owner",
        ],
    )

    session = MagicMock()
    monkeypatch.setattr(module, "SessionLocal", MagicMock(return_value=session))
    calls: dict[str, object] = {}

    def _create_user(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(id=42, username=kwargs["username"])

    monkeypatch.setattr(module, "create_user", _create_user)
    monkeypatch.setattr("app.core.security.hash_password", lambda _raw: "HASH_SENTINEL")

    module.main()

    captured = capsys.readouterr()
    assert generated_password not in captured.out + captured.err
    assert "HASH_SENTINEL" not in captured.out + captured.err
    assert calls["password_hash"] == "HASH_SENTINEL"
    assert calls["password_hash"] != generated_password
    assert calls["role"] == "admin"
    assert calls["is_active"] is True
    session.close.assert_called_once_with()
