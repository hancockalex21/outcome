from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from outcome.api.routes.health import router as health_router
from outcome.core.config import get_settings
from outcome.core.logging import configure_logging
from outcome.core.telemetry import configure_telemetry


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(title="Outcome", version="0.1.0", docs_url=None, redoc_url=None)
    app.include_router(health_router)
    configure_telemetry(app, settings)

    return app


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "outcome.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.env == "local",
    )
