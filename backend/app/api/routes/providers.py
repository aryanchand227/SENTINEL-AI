"""
SENTINEL AI — Provider status and health endpoints.

GET /api/v1/providers/status  — Provider connectivity, version, data mode, and mappings
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from backend.app.api.dependencies import get_current_user, get_siem_provider
from backend.app.core.config import Settings, get_settings
from backend.app.persistence.models import User
from backend.app.siem.provider_interface import ProviderHealthResult, ProviderInterface

router = APIRouter()


class ProviderStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    data_mode: str
    is_synthetic: bool
    health: ProviderHealthResult
    field_mappings: dict[str, str]


@router.get("/status", response_model=ProviderStatusResponse)
async def get_provider_status(
    current_user: User = Depends(get_current_user),
    provider: ProviderInterface = Depends(get_siem_provider),
    settings: Settings = Depends(get_settings),
) -> ProviderStatusResponse:
    """Return health check and field mappings for the configured provider."""
    health = await provider.health_check()
    mappings = await provider.get_field_mappings()

    return ProviderStatusResponse(
        provider=provider.name,
        data_mode=settings.sentinel_data_mode.value,
        is_synthetic=settings.is_synthetic_mode(),
        health=health,
        field_mappings=mappings,
    )
