"""
Unit tests for security utilities.
"""

from datetime import UTC, datetime, timedelta

import pytest

from backend.app.core.security import (
    UserRole,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        password = "SecureP@ss123!"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed) is True

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False


class TestJWT:
    def test_create_and_decode_token(self) -> None:
        token = create_access_token("user-123", UserRole.ANALYST)
        payload = decode_access_token(token)
        assert payload.sub == "user-123"
        assert payload.role == UserRole.ANALYST
        assert payload.exp > datetime.now(UTC)

    def test_expired_token_raises(self) -> None:
        token = create_access_token(
            "user-123",
            UserRole.ANALYST,
            expires_delta=timedelta(seconds=-10),
        )
        with pytest.raises(ValueError, match="Invalid token"):
            decode_access_token(token)

    def test_invalid_token_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid token"):
            decode_access_token("not.a.valid.token")
