"""
SENTINEL AI — Security utilities: JWT, password hashing, RBAC.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel

from backend.app.core.config import get_settings


class UserRole(StrEnum):
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    ADMIN = "admin"


class TokenPayload(BaseModel):
    sub: str  # user id
    role: UserRole
    exp: datetime


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(
    user_id: str,
    role: UserRole,
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {"sub": user_id, "role": role.value, "exp": expire}
    encoded = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return str(encoded)


def decode_access_token(token: str) -> TokenPayload:
    settings = get_settings()
    try:
        data = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return TokenPayload(
            sub=data["sub"],
            role=UserRole(data["role"]),
            exp=datetime.fromtimestamp(data["exp"], tz=UTC),
        )
    except (JWTError, KeyError, ValueError) as exc:
        raise ValueError(f"Invalid token: {exc}") from exc
