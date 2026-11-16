"""
Unit tests for Wazuh Provider Adapter.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from backend.app.core.config import Settings
from backend.app.domain.events import EventCategory, EventKind
from backend.app.siem.provider_interface import ProviderStatus, SearchRequest
from backend.app.siem.wazuh.adapter import (
    WazuhProvider,
    _map_wazuh_level_to_severity,
    _normalize_wazuh_alert,
)


def test_wazuh_severity_mapping() -> None:
    assert _map_wazuh_level_to_severity(1) == 25
    assert _map_wazuh_level_to_severity(3) == 25
    assert _map_wazuh_level_to_severity(4) == 50
    assert _map_wazuh_level_to_severity(7) == 50
    assert _map_wazuh_level_to_severity(8) == 75
    assert _map_wazuh_level_to_severity(11) == 75
    assert _map_wazuh_level_to_severity(12) == 100
    assert _map_wazuh_level_to_severity(16) == 100


def test_normalize_wazuh_alert() -> None:
    raw_alert = {
        "id": "1642248000.12345",
        "timestamp": "2025-01-15T12:00:00Z",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
        },
        "agent": {
            "id": "001",
            "name": "ubuntu-srv-01",
        },
        "data": {
            "srcip": "198.51.100.55",
            "srcport": "44321",
            "dstuser": "guest",
        },
        "full_log": "Jan 15 12:00:00 ubuntu sshd[1234]: Failed password for invalid user guest",
    }

    event = _normalize_wazuh_alert(raw_alert)
    assert event.event.id == "wazuh-1642248000.12345"
    assert event.event.kind == EventKind.ALERT
    assert event.event.severity == 75
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.agent is not None and event.agent.name == "ubuntu-srv-01"
    assert event.rule is not None and event.rule.id == "5710"
    assert event.source is not None and event.source.ip == "198.51.100.55"
    assert event.source.port == 44321
    assert event.user is not None and event.user.name == "guest"
    assert event.sentinel.source.provider == "wazuh"


@pytest.fixture
def mock_http_client() -> AsyncMock:
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def wazuh_settings() -> Settings:
    return Settings(
        wazuh_api_url="https://wazuh-mgr:55000",
        wazuh_api_username="wazuh-user",
        wazuh_api_password="wazuh-password",
        query_timeout_seconds=5,
    )


@pytest.mark.asyncio
async def test_wazuh_health_check_healthy(
    mock_http_client: AsyncMock, wazuh_settings: Settings
) -> None:
    # Auth response
    auth_resp = MagicMock(spec=httpx.Response)
    auth_resp.status_code = 200
    auth_resp.json.return_value = {"data": {"token": "test-jwt-token"}}

    # Status response
    status_resp = MagicMock(spec=httpx.Response)
    status_resp.status_code = 200
    status_resp.json.return_value = {"data": {"status": "running"}}

    mock_http_client.post.return_value = auth_resp
    mock_http_client.get.return_value = status_resp

    provider = WazuhProvider(http_client=mock_http_client, settings=wazuh_settings)
    health = await provider.health_check()

    assert health.provider == "wazuh"
    assert health.status == ProviderStatus.HEALTHY
    assert "responsive" in (health.message or "")


@pytest.mark.asyncio
async def test_wazuh_health_check_auth_failure(
    mock_http_client: AsyncMock, wazuh_settings: Settings
) -> None:
    auth_resp = MagicMock(spec=httpx.Response)
    auth_resp.status_code = 401
    mock_http_client.post.side_effect = httpx.HTTPStatusError(
        "Unauthorized", request=MagicMock(), response=auth_resp
    )

    provider = WazuhProvider(http_client=mock_http_client, settings=wazuh_settings)
    health = await provider.health_check()

    assert health.status == ProviderStatus.AUTH_FAILURE


@pytest.mark.asyncio
async def test_wazuh_search_success_with_aggregation(
    mock_http_client: AsyncMock, wazuh_settings: Settings
) -> None:
    # Auth response
    auth_resp = MagicMock(spec=httpx.Response)
    auth_resp.status_code = 200
    auth_resp.json.return_value = {"data": {"token": "test-jwt-token"}}

    # Alerts response
    alerts_resp = MagicMock(spec=httpx.Response)
    alerts_resp.status_code = 200
    alerts_resp.json.return_value = {
        "data": {
            "total_affected_items": 2,
            "affected_items": [
                {
                    "id": "1",
                    "timestamp": "2025-01-15T12:00:00Z",
                    "rule": {"id": "1001", "level": 12, "description": "Rootkit detected"},
                    "agent": {"id": "001", "name": "srv-alpha"},
                    "data": {"srcip": "10.0.0.5"},
                },
                {
                    "id": "2",
                    "timestamp": "2025-01-15T12:01:00Z",
                    "rule": {"id": "1001", "level": 12, "description": "Rootkit detected"},
                    "agent": {"id": "002", "name": "srv-beta"},
                    "data": {"srcip": "10.0.0.6"},
                },
            ],
        }
    }

    mock_http_client.post.return_value = auth_resp
    mock_http_client.get.return_value = alerts_resp

    provider = WazuhProvider(http_client=mock_http_client, settings=wazuh_settings)
    req = SearchRequest(
        aggregations=[{"type": "terms", "field": "agent.name", "name": "by_agent"}]
    )
    res = await provider.search(req)

    assert res.metadata.total_hits == 2
    assert len(res.events) == 2
    assert res.events[0].event.severity == 100
    assert len(res.aggregations) == 1
    assert res.aggregations[0].name == "by_agent"
    agent_counts = {b.key: b.doc_count for b in res.aggregations[0].buckets}
    assert agent_counts["srv-alpha"] == 1
    assert agent_counts["srv-beta"] == 1
