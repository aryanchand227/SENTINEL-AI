"""
Integration tests for authentication API endpoints.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.persistence.database import init_db
from backend.app.persistence.models import User


@pytest.fixture(autouse=True)
async def setup_test_db() -> None:
    await init_db()


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestAuthAPI:
    @pytest.mark.asyncio
    async def test_login_and_me(self, client: AsyncClient) -> None:
        import uuid
        test_email = f"analyst_{uuid.uuid4().hex[:6]}@sentinel.ai"
        test_pass = "MyP@ssword123!"

        # Seed user directly
        from backend.app.persistence.database import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            user = User(
                email=test_email,
                password_hash=hash_password(test_pass),
                display_name="Test Analyst",
                role="analyst",
            )
            session.add(user)
            await session.commit()

        # Attempt login
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": test_email, "password": test_pass},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        assert token_data["email"] == test_email
        token = token_data["access_token"]

        # Call /me with Bearer token
        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["email"] == test_email
        assert me_data["display_name"] == "Test Analyst"

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, client: AsyncClient) -> None:
        res = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@sentinel.ai", "password": "WrongPassword!"},
        )
        assert res.status_code == 401
