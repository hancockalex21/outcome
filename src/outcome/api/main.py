from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse

from outcome.api.routes.beta import BetaRouteDependencies
from outcome.api.routes.beta import router as beta_router
from outcome.api.routes.health import router as health_router
from outcome.core.config import Settings, get_settings, validate_startup_config
from outcome.core.logging import configure_logging
from outcome.core.telemetry import configure_telemetry


def create_app(
    *,
    settings: Settings | None = None,
    beta_session_factory: Callable[[], Session] | None = None,
    beta_redis: Redis | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    validate_startup_config(settings, process_role="api")

    app = FastAPI(title="Outcome", version="0.1.0", docs_url=None, redoc_url=None)
    if settings.beta_registration_enabled and beta_session_factory is None:
        engine = create_engine(settings.beta_registration_database_url, pool_pre_ping=True)
        beta_session_factory = sessionmaker(bind=engine)
    if settings.beta_registration_enabled and beta_redis is None:
        beta_redis = Redis.from_url(
            settings.redis_url,
            socket_connect_timeout=settings.redis_socket_timeout_seconds,
            socket_timeout=settings.redis_socket_timeout_seconds,
        )
    app.state.beta_registration = BetaRouteDependencies(
        settings=settings,
        session_factory=beta_session_factory,
        redis=beta_redis,
    )
    if settings.allowed_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_cors_origins),
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Outcome-Beta-Token",
                "X-Request-ID",
            ],
        )

    @app.middleware("http")
    async def bounded_requests(request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse({"detail": "invalid content length"}, status_code=400)
            if length > settings.api_request_max_bytes:
                return JSONResponse({"detail": "request too large"}, status_code=413)
        raw_request_id = request.headers.get("x-request-id")
        request_id = _bounded_request_id(raw_request_id)
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    app.include_router(health_router)
    app.include_router(beta_router)
    configure_telemetry(app, settings)

    return app


app = create_app()


def run() -> None:
    settings = get_settings()
    validate_startup_config(settings, process_role="api")
    uvicorn.run(
        "outcome.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
    )


def _bounded_request_id(value: str | None) -> str:
    if value is None or not 1 <= len(value) <= 128:
        return str(uuid4())
    if all(character.isalnum() or character in {"-", "_", "."} for character in value):
        return value
    return str(uuid4())
