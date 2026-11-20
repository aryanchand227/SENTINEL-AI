"""
Integration tests for health endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.orm import class_mapper

from backend.app.main import app
from backend.app.persistence.database import get_db_session
from backend.app.persistence.models import (
    AuditEvent,
    Conversation,
    EvidenceReference,
    Finding,
    Investigation,
    Message,
    QueryExecution,
    Report,
    User,
)


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_liveness(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/health/live")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "sentinel-ai"

    @pytest.mark.asyncio
    async def test_readiness_synthetic(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["provider"] == "synthetic"
        assert data["data_mode"] == "synthetic"
        assert data["checks"]["provider"] == "ok"
        assert data["checks"]["database"] == "ok"

    @pytest.mark.asyncio
    async def test_database_health_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/health/db")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["database"] in ("sqlite", "postgresql")
        assert data["latency_ms"] >= 0.0
        assert data["error"] is None

    @pytest.mark.asyncio
    async def test_database_session_lifecycle(self) -> None:
        # 1. Normal commit lifecycle
        session_gen = get_db_session()
        session = await anext(session_gen)
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1
        # Close generator (triggers commit)
        with pytest.raises(StopAsyncIteration):
            await anext(session_gen)

        # 2. Rollback lifecycle on error
        error_gen = get_db_session()
        await anext(error_gen)
        with pytest.raises(RuntimeError):
            try:
                raise RuntimeError("Simulated transaction error")
            except RuntimeError as exc:
                await error_gen.athrow(exc)

    @pytest.mark.asyncio
    async def test_orm_models_mapping(self) -> None:
        models = [
            User,
            Conversation,
            Message,
            Investigation,
            QueryExecution,
            EvidenceReference,
            Finding,
            Report,
            AuditEvent,
        ]
        for model in models:
            mapper = class_mapper(model)
            assert mapper is not None
            assert len(mapper.columns) > 0
            assert model.__tablename__ is not None
