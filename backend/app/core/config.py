
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

    model_config = SettingsConfigDict(
        env_file="backend/.env",
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


settings = Settings()
