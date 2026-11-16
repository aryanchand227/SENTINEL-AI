"""
Integration tests for queries API: preview and execute.
"""

from datetime import UTC, datetime, timedelta

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


class TestQueriesAPI:
    @pytest.mark.asyncio
    async def test_preview_valid_query(self, client: AsyncClient) -> None:
        now = datetime.now(UTC)
        spec = {
            "provider": "synthetic",
            "time_range": {
                "start": (now - timedelta(hours=24)).isoformat(),
                "end": now.isoformat(),
            },
            "filters": [
                {"field": "event.category", "operator": "eq", "value": "authentication"},
                {"field": "event.outcome", "operator": "eq", "value": "failure"},
            ],
            "aggregations": [
                {"type": "terms", "field": "source.ip", "size": 5},
            ],
            "intent": "Show failed logins",
        }
        res = await client.post("/api/v1/queries/preview", json={"spec": spec})
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is True
        assert len(data["errors"]) == 0
        assert data["compiled_request"] is not None
        assert data["provider"] == "synthetic"
        assert data["data_mode"] == "synthetic"

    @pytest.mark.asyncio
    async def test_preview_invalid_field(self, client: AsyncClient) -> None:
        now = datetime.now(UTC)
        spec = {
            "provider": "synthetic",
            "time_range": {
                "start": (now - timedelta(hours=1)).isoformat(),
                "end": now.isoformat(),
            },
            "filters": [
                {"field": "arbitrary_unsafe_field", "operator": "eq", "value": "x"},
            ],
            "intent": "Malicious search",
        }
        res = await client.post("/api/v1/queries/preview", json={"spec": spec})
        assert res.status_code == 200
        data = res.json()
        assert data["is_valid"] is False
        assert any(e["error_code"] == "UNAPPROVED_FIELD" for e in data["errors"])

    @pytest.mark.asyncio
    async def test_execute_valid_query(self, client: AsyncClient) -> None:
        # Base time matches synthetic data base time
        base = datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC)
        spec = {
            "provider": "synthetic",
            "time_range": {
                "start": (base - timedelta(hours=24)).isoformat(),
                "end": base.isoformat(),
            },
            "filters": [
                {"field": "source.ip", "operator": "eq", "value": "192.168.1.100"},
            ],
            "aggregations": [
                {"type": "terms", "field": "user.name", "size": 5},
            ],
            "intent": "Find events from SSH brute force IP",
        }
        res = await client.post("/api/v1/queries/execute", json={"spec": spec})
        assert res.status_code == 200
        data = res.json()
        assert data["provider"] == "synthetic"
        assert data["data_mode"] == "synthetic"
        assert data["metadata"]["total_hits"] == 20
        assert len(data["events"]) == 20
        assert len(data["aggregations"]) == 1

    @pytest.mark.asyncio
    async def test_execute_invalid_query_rejected(self, client: AsyncClient) -> None:
        now = datetime.now(UTC)
        spec = {
            "provider": "synthetic",
            "time_range": {
                "start": (now - timedelta(days=60)).isoformat(),  # exceeds max window
                "end": now.isoformat(),
            },
            "intent": "Unbounded search",
        }
        res = await client.post("/api/v1/queries/execute", json={"spec": spec})
        assert res.status_code == 400
        assert "Query validation failed" in res.json()["detail"]
