"""
SENTINEL AI — Health check endpoints.

GET /api/v1/health/live   — Process liveness (always 200 if running)
GET /api/v1/health/ready  — Dependency readiness check
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text

from backend.app.core.config import get_settings
from backend.app.persistence.database import get_engine

router = APIRouter()


class LivenessResponse(BaseModel):
    status: str = "ok"
    service: str = "sentinel-ai"


class ReadinessResponse(BaseModel):
    status: str  # "ready" or "degraded"
    provider: str
    data_mode: str
    checks: dict[str, str]


@router.get("/live", response_model=LivenessResponse)
async def liveness() -> LivenessResponse:
    """Process liveness probe."""
    return LivenessResponse()


@router.get("/ready", response_model=ReadinessResponse)
async def readiness() -> ReadinessResponse:
    """Dependency readiness check. Reports provider and database status."""
    settings = get_settings()
    checks: dict[str, str] = {}

    # Database check — actual live ping
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)[:50]}"

    # Provider check
    if settings.is_synthetic_mode():
        checks["provider"] = "ok"
    else:
        checks["provider"] = "not_configured"

    overall = "ready" if all(v == "ok" for v in checks.values()) else "degraded"

    return ReadinessResponse(
        status=overall,
        provider=settings.siem_provider.value,
        data_mode=settings.sentinel_data_mode.value,
        checks=checks,
    )
