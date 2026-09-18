from __future__ import annotations

from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse

from outcome.api.routes.health import router as health_router
from outcome.core.config import get_settings, validate_startup_config
from outcome.core.logging import configure_logging
from outcome.core.telemetry import configure_telemetry


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    validate_startup_config(settings, process_role="api")

    app = FastAPI(title="Outcome", version="0.1.0", docs_url=None, redoc_url=None)
    if settings.allowed_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_cors_origins),
            allow_credentials=False,
            allow_methods=["POST", "GET"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
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
