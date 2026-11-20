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

    # Initialize database tables
    from backend.app.persistence.database import init_db

    await init_db()

    # Ensure default analyst user exists
    from sqlalchemy import select

    from backend.app.core.security import hash_password
    from backend.app.persistence.database import get_session_factory
    from backend.app.persistence.models import User

    factory = get_session_factory()
    async with factory() as session:
        user_exists = (
            await session.execute(select(User).where(User.email == "analyst@sentinel.ai"))
        ).scalar_one_or_none()
        if user_exists is None:
            demo_user = User(
                email="analyst@sentinel.ai",
                password_hash=hash_password("Sentinel123!"),
                display_name="Demo SOC Analyst",
                role="analyst",
            )
            session.add(demo_user)
            await session.commit()
            logger.info("Initialized default analyst account: analyst@sentinel.ai")

    yield

    from backend.app.persistence.database import close_db
    from backend.app.siem.registry import get_provider_registry

    await get_provider_registry().close_all()
    await close_db()

    logger.info("SENTINEL AI shutting down.")
