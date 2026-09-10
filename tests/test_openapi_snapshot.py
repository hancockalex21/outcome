from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI

from outcome.schemas.v1 import (
    AuthorizeRequest,
    AuthorizeResponse,
    CapabilitiesResponse,
    PricingResponse,
    ReceiptResponse,
    StatusResponse,
    VerifyRequest,
    VerifyResponse,
)

SNAPSHOT_PATH = Path(__file__).parent / "snapshots" / "openapi_v1.json"


def build_contract_app() -> FastAPI:
    app = FastAPI(title="Outcome Contract", version="0.1.0")

    @app.post("/v1/verify", response_model=VerifyResponse)
    async def verify(_: VerifyRequest) -> None:
        raise NotImplementedError

    @app.post("/v1/authorize", response_model=AuthorizeResponse)
    async def authorize(_: AuthorizeRequest) -> None:
        raise NotImplementedError

    @app.get("/v1/receipts/{id}", response_model=ReceiptResponse)
    async def receipt(id: str) -> None:
        raise NotImplementedError

    @app.get("/v1/capabilities", response_model=CapabilitiesResponse)
    async def capabilities() -> None:
        raise NotImplementedError

    @app.get("/v1/pricing", response_model=PricingResponse)
    async def pricing() -> None:
        raise NotImplementedError

    @app.get("/v1/status", response_model=StatusResponse)
    async def status() -> None:
        raise NotImplementedError

    return app


def test_openapi_contract_matches_snapshot() -> None:
    openapi = build_contract_app().openapi()
    actual = json.dumps(openapi, indent=2, sort_keys=True) + "\n"

    assert actual == SNAPSHOT_PATH.read_text()


def test_production_app_does_not_mount_v1_handlers() -> None:
    from outcome.api.main import app

    paths = {
        path for route in app.routes if isinstance((path := getattr(route, "path", None)), str)
    }

    assert "/v1/verify" not in paths
    assert "/v1/authorize" not in paths
