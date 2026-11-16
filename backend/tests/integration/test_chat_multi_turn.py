"""
Integration tests for Conversational Investigation & Multi-Turn Context Resolution.

Tests the required demonstration flow from Section 36:
1. "Find accounts with failed logins in the last 24 hours."
2. "Did any of those accounts log in successfully afterwards?"
"""

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


class TestChatMultiTurnInvestigation:
    @pytest.mark.asyncio
    async def test_section_36_demonstration_flow(self, client: AsyncClient) -> None:
        # Step 1: Create a conversation
        create_res = await client.post(
            "/api/v1/conversations",
            json={"title": "Demo Investigation: Brute Force", "provider": "synthetic"},
        )
        assert create_res.status_code == 200
        conv = create_res.json()
        conv_id = conv["id"]

        # Step 2: Turn 1 — "Find accounts with failed logins in the last 24 hours."
        turn1_res = await client.post(
            "/api/v1/chat",
            json={
                "conversation_id": conv_id,
                "message": "Find accounts with failed logins in the last 24 hours.",
            },
        )
        assert turn1_res.status_code == 200
        data1 = turn1_res.json()
        assert data1["validation_status"] == "valid"
        assert data1["result_count"] > 0
        assert len(data1["evidence_ids"]) > 0
        assert len(data1["findings"]) > 0
        assert data1["findings"][0]["finding_type"] == "authentication_anomaly"

        # Step 3: Turn 2 — Follow-up: "Did any of those accounts log in successfully afterwards?"
        turn2_res = await client.post(
            "/api/v1/chat",
            json={
                "conversation_id": conv_id,
                "message": "Did any of those accounts log in successfully afterwards?",
            },
        )
        assert turn2_res.status_code == 200
        data2 = turn2_res.json()
        assert data2["validation_status"] == "valid"
        # In synthetic scenario 2, jsmith had 1 successful login after 15 failures
        assert data2["result_count"] >= 1
        assert len(data2["findings"]) > 0
        assert data2["findings"][0]["finding_type"] == "post_failure_success"
        assert data2["findings"][0]["severity"] == "critical"
        assert any("jsmith" in data2["assistant_message"] for _ in [0])

        # Step 4: Verify conversation history retrieval
        history_res = await client.get(f"/api/v1/conversations/{conv_id}")
        assert history_res.status_code == 200
        history_data = history_res.json()
        assert len(history_data["messages"]) == 4  # 2 user messages + 2 assistant responses
        assert history_data["messages"][0]["role"] == "user"
        assert history_data["messages"][1]["role"] == "assistant"
        assert history_data["messages"][2]["role"] == "user"
        assert history_data["messages"][3]["role"] == "assistant"
