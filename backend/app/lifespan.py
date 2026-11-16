"""
SENTINEL AI — Application lifespan management.

Handles startup/shutdown tasks: DB connections, provider initialization, etc.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown hooks."""
    settings = get_settings()
    logger.info(
        "SENTINEL AI starting — env=%s provider=%s data_mode=%s",
        settings.app_env.value,
        settings.siem_provider.value,
        settings.sentinel_data_mode.value,
    )

    # Ensure report storage directory exists
    settings.report_storage_path.mkdir(parents=True, exist_ok=True)

    yield

    logger.info("SENTINEL AI shutting down.")
