from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from outcome.api.main import app


async def test_healthz_returns_ok() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
