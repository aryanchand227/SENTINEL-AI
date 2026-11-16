"""
Integration tests for providers status API.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.persistence.database import init_db


@pytest.fixture(autouse=True)
async def setup_test_db() -> None:
    await init_db()


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestProvidersAPI:
    @pytest.mark.asyncio
    async def test_provider_status(self, client: AsyncClient) -> None:
        res = await client.get("/api/v1/providers/status")
        assert res.status_code == 200
        data = res.json()
        assert data["provider"] == "synthetic"
        assert data["data_mode"] == "synthetic"
        assert data["is_synthetic"] is True
        assert data["health"]["status"] == "healthy"
        assert "@timestamp" in data["field_mappings"]
        assert "source.ip" in data["field_mappings"]
