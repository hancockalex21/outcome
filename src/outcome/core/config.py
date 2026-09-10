from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OUTCOME_", env_file=".env", extra="ignore")

    env: str = "local"
    log_level: str = "info"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = Field(default="postgresql+asyncpg://outcome@localhost:5432/outcome")
    redis_url: str = "redis://localhost:6379/0"
    otel_service_name: str = "outcome-api"
    otel_exporter_otlp_endpoint: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
