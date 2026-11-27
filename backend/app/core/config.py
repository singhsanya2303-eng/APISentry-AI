
import base64
import binascii
import re
from typing import Optional, List, Any
from urllib.parse import urlparse

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

# Encoded production secrets must represent at least 256 bits; format checks
# cannot prove randomness, so obvious repeated and sequential values are rejected.
_MIN_JWT_SECRET_BYTES = 32

# ENVIRONMENT is intentionally allowlisted. Production aliases such as `prod`
# must be rejected instead of silently behaving like development.
_ALLOWED_ENVIRONMENTS = frozenset(
    {"development", "dev", "local", "test", "testing", "staging", "production"}
)

# Public registration is a deliberate opt-in and never enabled in production.
_REGISTRATION_FLAG = "APISENTRY_ENABLE_PUBLIC_REGISTRATION"

# Placeholder markers reject copied template values without echoing them in errors.
_PLACEHOLDER_SECRET_MARKERS = (
    "replace_with",
    "change_me",
    "changeme",
    "placeholder",
    "your_",
    "local-development-only",
    "<",
    ">",
)


class Settings(BaseSettings):
    _DEVELOPMENT_JWT_SECRET = "local-development-only-jwt-secret"

    # Application Configuration
    PROJECT_NAME: str = "APISentry AI"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_KEY: str = ""
    API_V1_STR: str = "/api/v1"

    # JWT Authentication Configuration
    JWT_SECRET_KEY: str = _DEVELOPMENT_JWT_SECRET
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # CORS Configuration
    # Configure trusted frontend origins in backend/.env
    CORS_ORIGINS: List[str] = []

    # Network / Proxy Configuration
    TRUSTED_PROXIES: List[str] = []

    # API hardening defaults (safe local defaults; tune for production)
    MAX_REQUEST_BODY_BYTES: int = 1_048_576  # 1 MiB
    AUTH_RATE_LIMIT_ENABLED: bool = True
    AUTH_RATE_LIMIT_REQUESTS: int = 20
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60
    SECURITY_HEADERS_ENABLED: bool = True

    # Database Configuration (Environment managed)
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "apisentry_db"
    DATABASE_URL: Optional[str] = None

    # Startup schema creation gate. Production always forces this to False.
    AUTO_CREATE_SCHEMA: bool = True

    # Public self-registration is disabled by default and can never be enabled
    # in production. Owner-controlled provisioning remains available through
    # the trusted service/database path, not an unauthenticated HTTP bootstrap.
    APISENTRY_ENABLE_PUBLIC_REGISTRATION: bool = False

    # Demo Authentication Feature Flag (Strictly disabled by default, never enabled in production)
    APISENTRY_ENABLE_DEMO_AUTH: bool = False
    DEMO_USERNAME: str = "demo_user"
    DEMO_PASSWORD: Optional[str] = None

    # Demo control-plane routers (Gate E / WP9) are never mounted in production
    # and require an explicit opt-in in a non-production environment.
    APISENTRY_ENABLE_DEMO_CONTROL_PLANE: bool = False

    # Gate E isolated local demo-only persistence directory (non-secret).
    # Empty default resolves to a safe temp subdirectory at runtime.
    # Configured paths must resolve under the system temp directory to prevent
    # arbitrary filesystem writes.
    MITIGATION_DEMO_DB_DIR: str = ""

    model_config = SettingsConfigDict(
        env_file=["backend/.env", ".env"],
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @field_validator("TRUSTED_PROXIES", mode="before")
    @classmethod
    def assemble_trusted_proxies(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            val = v.strip()

            if not val:
                return []

            if val.startswith("[") and val.endswith("]"):
                import json

                try:
                    return json.loads(val)
                except (ValueError, TypeError):
                    pass

            return [
                item.strip()
                for item in val.split(",")
                if item.strip()
            ]

        if isinstance(v, (list, tuple, set)):
            return [
                str(item).strip()
                for item in v
                if str(item).strip()
            ]

        return []

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def normalize_environment(cls, value: Any) -> str:
        normalized = str(value).strip().lower()
        if normalized != "production" and (
            "prod" in normalized or normalized in {"prd", "live"}
        ):
            raise ValueError(
                "ENVIRONMENT is ambiguous; use the exact value 'production' for production deployments"
            )
        if normalized not in _ALLOWED_ENVIRONMENTS:
            raise ValueError(
                "ENVIRONMENT must be one of: development, dev, local, test, testing, staging, production"
            )
        return normalized

    @field_validator("MAX_REQUEST_BODY_BYTES")
    @classmethod
    def validate_request_body_limit(cls, value: int) -> int:
        if int(value) < 1024 or int(value) > 100 * 1024 * 1024:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be between 1024 and 104857600")
        return int(value)

    @field_validator("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    @classmethod
    def validate_token_lifetime(cls, value: int) -> int:
        if int(value) < 1 or int(value) > 10080:
            raise ValueError("JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be between 1 and 10080")
        return int(value)

    @field_validator("AUTH_RATE_LIMIT_REQUESTS")
    @classmethod
    def validate_auth_rate_limit_requests(cls, value: int) -> int:
        if int(value) < 1 or int(value) > 100_000:
            raise ValueError("AUTH_RATE_LIMIT_REQUESTS must be between 1 and 100000")
        return int(value)

    @field_validator("AUTH_RATE_LIMIT_WINDOW_SECONDS")
    @classmethod
    def validate_auth_rate_limit_window(cls, value: int) -> int:
        if int(value) < 1 or int(value) > 86_400:
            raise ValueError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be between 1 and 86400")
        return int(value)

    @classmethod
    def _is_obviously_predictable_secret(cls, secret: str) -> bool:
        if len(set(secret)) <= 2:
            return True

        for unit_length in range(1, min(8, len(secret) // 2) + 1):
            if len(secret) % unit_length == 0:
                unit = secret[:unit_length]
                if secret == unit * (len(secret) // unit_length):
                    return True

        return all(
            ord(current) + 1 == ord(next_character)
            for current, next_character in zip(secret, secret[1:])
        )

    @classmethod
    def _is_placeholder_secret(cls, secret: str) -> bool:
        lowered = secret.strip().lower()
        return any(marker in lowered for marker in _PLACEHOLDER_SECRET_MARKERS)

    @classmethod
    def _meets_jwt_secret_requirements(cls, secret: str) -> bool:
        if cls._is_obviously_predictable_secret(secret):
            return False
        if cls._is_placeholder_secret(secret):
            return False

        if len(secret) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", secret):
            try:
                return len(bytes.fromhex(secret)) >= _MIN_JWT_SECRET_BYTES
            except ValueError:
                return False

        if len(secret) == 43 and re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
            try:
                padding = "=" * (-len(secret) % 4)
                decoded = base64.urlsafe_b64decode(secret + padding)
            except (binascii.Error, ValueError):
                return False
            return len(decoded) >= _MIN_JWT_SECRET_BYTES

        return False

    def _production_database_target_configured(self) -> bool:
        """True only for an explicit PostgreSQL DSN or full PostgreSQL target."""
        if self.DATABASE_URL and self.DATABASE_URL.strip():
            try:
                parsed = make_url(self.DATABASE_URL)
            except Exception:
                return False
            if parsed.get_backend_name() not in {
                "postgresql",
                "postgresql+psycopg2",
                "postgresql+psycopg",
            }:
                return False
            return bool(parsed.host and parsed.database)
        required_fields = (
            "POSTGRES_SERVER",
            "POSTGRES_PORT",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "POSTGRES_DB",
        )
        return all(
            field in self.model_fields_set
            and str(getattr(self, field)).strip()
            for field in required_fields
        )

    @model_validator(mode="after")
    def validate_security_configuration(self) -> "Settings":
        normalized_origins: List[str] = []
        for origin in self.CORS_ORIGINS:
            o = str(origin).strip()
            if not o:
                continue
            if o == "*":
                raise ValueError("CORS_ORIGINS must not include '*' when credentials are supported")
            parsed = urlparse(o)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("CORS_ORIGINS entries must be absolute http(s) origins")
            normalized_origins.append(o.rstrip("/"))
        self.CORS_ORIGINS = normalized_origins

        if self.is_production:
            # Production must fail closed on every deployment-shaping setting.
            self.DEBUG = False
            self.AUTO_CREATE_SCHEMA = False
            self.APISENTRY_ENABLE_DEMO_AUTH = False
            self.APISENTRY_ENABLE_DEMO_CONTROL_PLANE = False

            if _REGISTRATION_FLAG not in self.model_fields_set:
                raise ValueError(
                    "APISENTRY_ENABLE_PUBLIC_REGISTRATION must be explicitly set to false in production"
                )
            if self.APISENTRY_ENABLE_PUBLIC_REGISTRATION:
                raise ValueError(
                    "APISENTRY_ENABLE_PUBLIC_REGISTRATION cannot be enabled in production"
                )
            self.APISENTRY_ENABLE_PUBLIC_REGISTRATION = False
            if not self.CORS_ORIGINS:
                raise ValueError("CORS_ORIGINS must contain explicit trusted origins in production")
            for origin in self.CORS_ORIGINS:
                parsed = urlparse(origin)
                if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
                    raise ValueError(
                        "CORS_ORIGINS must use https in production except for loopback development origins"
                    )
            if not self._production_database_target_configured():
                raise ValueError(
                    "Production requires an explicit DATABASE_URL with a PostgreSQL scheme, "
                    "host and database, or all POSTGRES_SERVER, POSTGRES_PORT, POSTGRES_USER, "
                    "POSTGRES_PASSWORD and POSTGRES_DB values"
                )

            database_password = None
            if self.DATABASE_URL and self.DATABASE_URL.strip():
                try:
                    database_password = make_url(self.DATABASE_URL).password
                except Exception:
                    database_password = None
            else:
                database_password = self.POSTGRES_PASSWORD
            if database_password and self._is_placeholder_secret(database_password):
                raise ValueError(
                    "Production database credentials must not be template placeholder values"
                )
            if self.API_KEY.strip() and self._is_placeholder_secret(self.API_KEY.strip()):
                raise ValueError(
                    "API_KEY must be a generated service key or empty in production"
                )

            secret = self.JWT_SECRET_KEY.strip()
            if (
                not secret
                or secret == self._DEVELOPMENT_JWT_SECRET
                or not self._meets_jwt_secret_requirements(secret)
            ):
                raise ValueError(
                    "JWT_SECRET_KEY must encode at least 256 bits and not be an insecure "
                    "default or obviously predictable value in production"
                )
        return self

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL

        # URL.create escapes reserved characters in managed-PG credentials.
        # The returned string is used only for engine creation; it is never logged.
        return URL.create(
            "postgresql",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        ).render_as_string(hide_password=False)

    @property
    def is_production(self) -> bool:
        """Exact production token after normalization, used by all safety gates."""
        return str(self.ENVIRONMENT).strip().lower() == "production"

    @property
    def is_public_registration_enabled(self) -> bool:
        """Public registration is opt-in only and impossible in production."""
        if self.is_production:
            return False
        return bool(self.APISENTRY_ENABLE_PUBLIC_REGISTRATION)

    @property
    def is_demo_auth_enabled(self) -> bool:
        """Demo authentication endpoint is strictly disabled by default and never allowed in production."""
        if self.is_production:
            return False
        return bool(self.APISENTRY_ENABLE_DEMO_AUTH and self.DEMO_PASSWORD)

    @property
    def is_demo_control_plane_enabled(self) -> bool:
        """Gate E / WP9 demo routers require explicit non-production opt-in."""
        if self.is_production:
            return False
        return bool(self.APISENTRY_ENABLE_DEMO_CONTROL_PLANE)

    def deployment_summary(self) -> dict[str, Any]:
        """Non-secret configuration snapshot for startup logs and health checks."""
        return {
            "environment": self.ENVIRONMENT,
            "debug": bool(self.DEBUG),
            "auto_create_schema": bool(self.AUTO_CREATE_SCHEMA),
            "public_registration_enabled": self.is_public_registration_enabled,
            "cors_origin_count": len(self.CORS_ORIGINS),
            "max_request_body_bytes": int(self.MAX_REQUEST_BODY_BYTES),
            "auth_rate_limit_enabled": bool(self.AUTH_RATE_LIMIT_ENABLED),
            "security_headers_enabled": bool(self.SECURITY_HEADERS_ENABLED),
            "demo_auth_enabled": self.is_demo_auth_enabled,
            "demo_control_plane_enabled": self.is_demo_control_plane_enabled,
            "database_configured": bool(self.DATABASE_URL or self.POSTGRES_PASSWORD),
            "enforcement_mode": "advisory_only",
            "production_request_middleware_registered": False,
        }


settings = Settings()
