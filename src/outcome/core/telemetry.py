from __future__ import annotations

from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import set_tracer_provider

from outcome.core.config import Settings


def configure_telemetry(app: FastAPI, settings: Settings) -> None:
    resource = Resource.create({"service.name": settings.otel_service_name})
    set_tracer_provider(TracerProvider(resource=resource))
    FastAPIInstrumentor.instrument_app(app)
