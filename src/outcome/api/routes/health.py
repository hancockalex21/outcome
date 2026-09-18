from __future__ import annotations

from fastapi import APIRouter
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from outcome.core.config import ConfigValidationError, get_settings, validate_startup_config
from outcome.schemas.health import HealthResponse

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse, include_in_schema=False)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/readyz", include_in_schema=False)
async def readyz() -> dict[str, object]:
    settings = get_settings()
    checks: dict[str, str] = {}
    try:
        validate_startup_config(settings, process_role="api")
        checks["config"] = "ok"
    except ConfigValidationError:
        checks["config"] = "failed"
    checks["database"] = await _check_database(settings.database_url)
    checks["redis"] = _check_redis(settings.redis_url, settings.redis_socket_timeout_seconds)
    status = "ok" if all(value == "ok" for value in checks.values()) else "degraded"
    return {"status": status, "checks": checks}


async def _check_database(database_url: str) -> str:
    try:
        engine = create_async_engine(database_url, pool_pre_ping=True)
        try:
            async with engine.connect() as connection:
                await connection.execute(text("select 1"))
        finally:
            await engine.dispose()
    except Exception:
        return "failed"
    return "ok"


def _check_redis(redis_url: str, timeout_seconds: int) -> str:
    try:
        client = Redis.from_url(
            redis_url,
            socket_connect_timeout=timeout_seconds,
            socket_timeout=timeout_seconds,
        )
        try:
            client.ping()
        finally:
            client.close()
    except RedisError:
        return "failed"
    return "ok"
