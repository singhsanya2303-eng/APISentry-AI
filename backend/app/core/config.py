
import base64
import binascii
import re
from typing import Optional, List, Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Encoded production secrets must represent at least 256 bits; format checks
# cannot prove randomness, so obvious repeated and sequential values are rejected.
_MIN_JWT_SECRET_BYTES = 32


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

    # Database Configuration (Environment managed)
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "apisentry_db"
    DATABASE_URL: Optional[str] = None

    # Demo Authentication Feature Flag (Strictly disabled by default, never enabled in production)
    APISENTRY_ENABLE_DEMO_AUTH: bool = False
    DEMO_USERNAME: str = "demo_user"
    DEMO_PASSWORD: Optional[str] = None

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
        return str(value).strip().lower()

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
    def _meets_jwt_secret_requirements(cls, secret: str) -> bool:
        if cls._is_obviously_predictable_secret(secret):
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

    @model_validator(mode="after")
    def validate_security_configuration(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            secret = self.JWT_SECRET_KEY.strip()
            if (
                not secret
                or secret == self._DEVELOPMENT_JWT_SECRET
                or not self._meets_jwt_secret_requirements(secret)
            ):
                raise ValueError(
                    "JWT_SECRET_KEY must encode at least 256 bits and not be obviously predictable in production"
                )
        return self

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL

        return (
            f"postgresql://{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:"
            f"{self.POSTGRES_PORT}/"
            f"{self.POSTGRES_DB}"
        )

    @property
    def is_demo_auth_enabled(self) -> bool:
        """Demo authentication endpoint is strictly disabled by default and never allowed in production."""
        if self.ENVIRONMENT == "production":
            return False
        return bool(self.APISENTRY_ENABLE_DEMO_AUTH and self.DEMO_PASSWORD)


settings = Settings()
