"""
SENTINEL AI — FastAPI API Dependencies.

Provides authenticated user injection, database sessions,
and configured SIEM provider instance.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import Settings, get_settings
from backend.app.core.security import decode_access_token
from backend.app.persistence.database import get_db_session
from backend.app.persistence.models import User
from backend.app.siem.provider_interface import ProviderInterface
from backend.app.siem.registry import get_provider_registry

security_scheme = HTTPBearer(auto_error=False)


def get_siem_provider(settings: Settings = Depends(get_settings)) -> ProviderInterface:
    """Active SIEM provider resolved via the provider registry."""
    return get_provider_registry(settings).get_provider()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(security_scheme),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> User:
    """
    Authenticate request via Bearer JWT.
    In development mode without credentials, ensures and returns a demo analyst user.
    """
    if credentials is None:
        if settings.app_env.value == "development":
            # Auto-seed demo analyst in dev mode for ease of local testing
            demo_user = (
                await session.execute(select(User).where(User.email == "analyst@sentinel.ai"))
            ).scalar_one_or_none()
            if demo_user is None:
                from backend.app.core.security import hash_password

                demo_user = User(
                    email="analyst@sentinel.ai",
                    password_hash=hash_password("Sentinel123!"),
                    display_name="Demo SOC Analyst",
                    role="analyst",
                )
                session.add(demo_user)
                await session.commit()
                await session.refresh(demo_user)
            return demo_user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    user = (await session.execute(select(User).where(User.id == payload.sub))).scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
