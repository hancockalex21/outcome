from __future__ import annotations

from fastapi import APIRouter

from outcome.schemas.health import HealthResponse

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse, include_in_schema=False)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok")
