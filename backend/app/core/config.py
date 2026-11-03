
from typing import Optional, List, Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Configuration
    PROJECT_NAME: str = "APISentry AI"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_KEY: str = ""
    API_V1_STR: str = "/api/v1"

    # JWT Authentication Configuration
    JWT_SECRET_KEY: str = "apisentry-insecure-default-jwt-secret-key-change-in-production"
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
        if str(self.ENVIRONMENT).lower() == "production":
            return False
        return bool(self.APISENTRY_ENABLE_DEMO_AUTH)


settings = Settings()
