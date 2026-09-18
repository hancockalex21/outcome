from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ProcessRole = Literal["api", "mcp", "worker"]


class ConfigValidationError(RuntimeError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OUTCOME_", env_file=".env", extra="ignore")

    env: str = "local"
    log_level: str = "info"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_request_max_bytes: int = Field(default=1_048_576, ge=1, le=8_388_608)
    allowed_cors_origins: tuple[str, ...] = ()
    database_url: str = Field(default="postgresql+asyncpg://outcome@localhost:5432/outcome")
    database_pool_size: int = Field(default=5, ge=1, le=20)
    database_max_overflow: int = Field(default=5, ge=0, le=20)
    database_pool_timeout_seconds: int = Field(default=5, ge=1, le=30)
    database_pool_recycle_seconds: int = Field(default=1800, ge=60, le=86_400)
    mcp_database_url: str = "sqlite:///outcome-mcp-local.db"
    mcp_http_host: str = "0.0.0.0"
    mcp_http_port: int = Field(default=8001, ge=1, le=65535)
    mcp_http_path: str = "/mcp"
    mcp_request_max_bytes: int = Field(default=1_048_576, ge=1, le=8_388_608)
    mcp_max_sessions: int = Field(default=1000, ge=1, le=10_000)
    mcp_session_idle_timeout_seconds: int = Field(default=900, ge=30, le=3600)
    mcp_allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    mcp_receipt_signing_key_id: str = "outcome-mcp-dev-key"
    mcp_receipt_private_key_b64: str = ""
    redis_url: str = "redis://localhost:6379/0"
    redis_socket_timeout_seconds: int = Field(default=3, ge=1, le=30)
    reservation_ttl_seconds: int = Field(default=900, ge=60, le=7200)
    max_billable_execution_window_seconds: int = Field(default=600, ge=30, le=3600)
    reservation_ttl_safety_margin_seconds: int = Field(default=120, ge=0, le=1800)
    stripe_funding_enabled: bool = False
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    worker_secret_resolver_backend: str = "development"
    allowed_provider_destinations: tuple[str, ...] = ()
    otel_service_name: str = "outcome-api"
    otel_exporter_otlp_endpoint: str = ""

    @field_validator(
        "allowed_cors_origins",
        "allowed_provider_destinations",
        "mcp_allowed_hosts",
        mode="before",
    )
    @classmethod
    def _split_csv_tuple(cls, value: object) -> tuple[str, ...]:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (tuple, list)):
            return tuple(str(item) for item in value)
        raise TypeError("expected comma-separated string or sequence")


@lru_cache
def get_settings() -> Settings:
    return Settings()


def validate_startup_config(settings: Settings, *, process_role: ProcessRole) -> None:
    errors: list[str] = []
    production = settings.env.lower() in {"production", "prod"}

    if not settings.database_url:
        errors.append("OUTCOME_DATABASE_URL is required")
    if not settings.redis_url:
        errors.append("OUTCOME_REDIS_URL is required")
    if settings.api_request_max_bytes > 8_388_608 or settings.mcp_request_max_bytes > 8_388_608:
        errors.append("request body limits must stay bounded")
    if settings.reservation_ttl_seconds < (
        settings.max_billable_execution_window_seconds
        + settings.reservation_ttl_safety_margin_seconds
    ):
        errors.append(
            "OUTCOME_RESERVATION_TTL_SECONDS must cover billable execution window plus margin"
        )
    if settings.reservation_ttl_seconds > 7200:
        errors.append("OUTCOME_RESERVATION_TTL_SECONDS is too large for controlled beta")

    if production:
        if "*" in settings.allowed_cors_origins:
            errors.append("wildcard CORS is not allowed in production")
        if "*" in settings.mcp_allowed_hosts:
            errors.append("wildcard MCP allowed hosts are not allowed in production")
        if process_role == "mcp" and not settings.mcp_allowed_hosts:
            errors.append("remote MCP requires at least one allowed host")
        if process_role in {"mcp", "api"} and settings.mcp_receipt_signing_key_id.endswith(
            "dev-key"
        ):
            errors.append("production receipt signing key id must not be a development key")
        if process_role == "mcp" and not settings.mcp_receipt_private_key_b64:
            errors.append("remote MCP authorization requires OUTCOME_MCP_RECEIPT_PRIVATE_KEY_B64")
        if process_role == "mcp" and settings.mcp_database_url.startswith("sqlite:"):
            errors.append("production remote MCP must not use local SQLite")
        if settings.stripe_funding_enabled and (
            not settings.stripe_secret_key or not settings.stripe_webhook_secret
        ):
            errors.append("Stripe funding requires Stripe secret and webhook secret")
        if process_role == "worker" and settings.worker_secret_resolver_backend == "development":
            errors.append("production worker must not use development secret resolver backend")

    if errors:
        raise ConfigValidationError("; ".join(errors))


__all__ = [
    "ConfigValidationError",
    "ProcessRole",
    "Settings",
    "get_settings",
    "validate_startup_config",
]
