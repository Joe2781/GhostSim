"""Central configuration for the GhostSim backend.

Secrets must be provided through environment variables or a
managed secrets provider. Never commit real secrets to Git.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


Environment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    """Validated settings loaded from the process environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    # Application
    app_name: str = "GhostSim API"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    debug: bool = False

    # Network binding
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # Database
    database_url: SecretStr | None = None
    database_host: str = "127.0.0.1"
    database_port: int = Field(default=5432, ge=1, le=65535)
    database_name: str = "ghostsim"
    database_user: str = "ghostsim_app"
    database_password: SecretStr | None = None
    database_ssl_required: bool = True
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=5, ge=0, le=100)
    database_pool_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=120,
    )

    # Frontend origins. Use explicit origins in production.
    cors_origins: list[str] = Field(default_factory=list)

    # Request protection
    max_request_body_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=20_971_520,
    )

    # Optional AI configuration.
    # AI must not be required for core connectivity or call signaling.
    gemini_api_key: SecretStr | None = None
    gemini_model: str | None = None
    ai_routing_enabled: bool = False

    # Future provider integration.
    # Payment credentials must be configured separately when
    # payment integration is implemented.
    flutterwave_secret_key: SecretStr | None = None

    # Health endpoint behavior
    expose_detailed_health: bool = False

    @field_validator("app_name")
    @classmethod
    def validate_app_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("APP_NAME cannot be empty.")
        return value

    @field_validator("database_name", "database_user")
    @classmethod
    def validate_database_identifiers(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Database name and user cannot be empty.")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value):
        """Accept either a JSON list or comma-separated origins."""
        if value is None or value == "":
            return []

        if isinstance(value, str):
            value = value.strip()

            if value.startswith("["):
                return value

            return [
                origin.strip().rstrip("/")
                for origin in value.split(",")
                if origin.strip()
            ]

        if isinstance(value, list):
            return [
                str(origin).strip().rstrip("/")
                for origin in value
                if str(origin).strip()
            ]

        raise ValueError(
            "CORS_ORIGINS must be a list or comma-separated string."
        )

    @field_validator("gemini_model")
    @classmethod
    def validate_gemini_model(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip()
            if not value:
                return None
        return value

    @model_validator(mode="after")
    def validate_environment_security(self):
        if self.environment == "production":
            if self.debug:
                raise ValueError(
                    "DEBUG must be false in production."
                )

            if not self.cors_origins:
                raise ValueError(
                    "Set explicit CORS_ORIGINS in production."
                )

            if not self.database_ssl_required:
                raise ValueError(
                    "DATABASE_SSL_REQUIRED must be true in production."
                )

            if self.host in {"127.0.0.1", "localhost"}:
                raise ValueError(
                    "Configure HOST for the production deployment."
                )

        if self.ai_routing_enabled and not self.gemini_api_key:
            raise ValueError(
                "AI_ROUTING_ENABLED requires GEMINI_API_KEY."
            )

        return self

    def get_database_url(self) -> str:
        """Return the configured PostgreSQL URL.

        DATABASE_URL takes precedence when supplied. Otherwise,
        construct the URL from the individual DB settings.
        """
        if self.database_url:
            raw_url = self.database_url.get_secret_value().strip()

            if not raw_url:
                raise ValueError("DATABASE_URL cannot be empty.")

            if not raw_url.startswith(
                ("postgresql://", "postgresql+asyncpg://")
            ):
                raise ValueError(
                    "DATABASE_URL must use PostgreSQL."
                )

            # SQLAlchemy's async engine requires asyncpg.
            if raw_url.startswith("postgresql://"):
                raw_url = raw_url.replace(
                    "postgresql://",
                    "postgresql+asyncpg://",
                    1,
                )

            if (
                self.environment == "production"
                and self.database_ssl_required
                and "ssl=" not in raw_url
                and "sslmode=" not in raw_url
            ):
                separator = "&" if "?" in raw_url else "?"
                raw_url = f"{raw_url}{separator}ssl=require"

            return raw_url

        if not self.database_password:
            raise ValueError(
                "Set DATABASE_URL or DATABASE_PASSWORD."
            )

        password = quote(
            self.database_password.get_secret_value(),
            safe="",
        )

        username = quote(self.database_user, safe="")
        database = quote(self.database_name, safe="")

        url = (
            f"postgresql+asyncpg://{username}:{password}"
            f"@{self.database_host}:{self.database_port}/{database}"
        )

        if (
            self.environment == "production"
            and self.database_ssl_required
        ):
            url += "?ssl=require"

        return url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return one validated settings instance per process."""
    return Settings()
