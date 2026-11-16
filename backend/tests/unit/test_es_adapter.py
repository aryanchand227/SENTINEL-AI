"""
Unit tests for Elasticsearch 8.x Provider Adapter.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from elasticsearch import ApiError, ConnectionError, ConnectionTimeout

from backend.app.core.config import Settings
from backend.app.domain.events import EventCategory, EventKind
from backend.app.siem.elasticsearch.adapter import ElasticsearchProvider
from backend.app.siem.provider_interface import ProviderStatus, SearchRequest


@pytest.fixture
def mock_es_client() -> AsyncMock:
    client = AsyncMock()
    return client


@pytest.fixture
def es_settings() -> Settings:
    return Settings(
        elasticsearch_url="https://mock-es:9200",
        elasticsearch_index_allowlist="logs-*,wazuh-alerts-*",
        query_timeout_seconds=5,
    )


@pytest.mark.asyncio
async def test_es_health_check_healthy(mock_es_client: AsyncMock, es_settings: Settings) -> None:
    mock_es_client.info.return_value = {
        "cluster_name": "sentinel-cluster",
        "version": {"number": "8.15.0"},
    }
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    health = await provider.health_check()

    assert health.provider == "elasticsearch"
    assert health.status == ProviderStatus.HEALTHY
    assert health.version == "8.15.0"
    assert "sentinel-cluster" in (health.message or "")


@pytest.mark.asyncio
async def test_es_health_check_connection_error(
    mock_es_client: AsyncMock, es_settings: Settings
) -> None:
    mock_es_client.info.side_effect = ConnectionError("Connection refused")
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    health = await provider.health_check()

    assert health.status == ProviderStatus.UNAVAILABLE
    assert "Cannot connect" in (health.message or "")


@pytest.mark.asyncio
async def test_es_health_check_auth_failure(
    mock_es_client: AsyncMock, es_settings: Settings
) -> None:
    mock_meta = MagicMock()
    mock_meta.status = 401
    mock_es_client.info.side_effect = ApiError(
        message="Unauthorized",
        meta=mock_meta,
        body={"error": "unauthorized"},
    )
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    health = await provider.health_check()

    assert health.status == ProviderStatus.AUTH_FAILURE


@pytest.mark.asyncio
async def test_es_search_success(mock_es_client: AsyncMock, es_settings: Settings) -> None:
    mock_es_client.search.return_value = {
        "_shards": {"total": 5, "successful": 5, "failed": 0},
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "doc123",
                    "_index": "logs-auth-2025",
                    "_source": {
                        "@timestamp": "2025-01-15T12:00:00Z",
                        "message": "User admin failed password authentication",
                        "event": {
                            "id": "ev-1",
                            "category": "authentication",
                            "action": "logon_failed",
                            "outcome": "failure",
                            "severity": 75,
                        },
                        "source": {"ip": "198.51.100.22", "port": 50123},
                        "user": {"name": "admin", "id": "1001"},
                        "host": {"name": "auth-srv-01"},
                    },
                }
            ],
        },
        "aggregations": {
            "top_users": {
                "buckets": [
                    {"key": "admin", "doc_count": 1},
                ]
            }
        },
    }

    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    res = await provider.search(SearchRequest())

    assert res.metadata.total_hits == 1
    assert res.metadata.returned_count == 1
    assert not res.metadata.is_partial
    assert len(res.events) == 1

    event = res.events[0]
    assert event.event.id == "ev-1"
    assert event.event.kind == EventKind.EVENT
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.user is not None and event.user.name == "admin"
    assert event.source is not None and event.source.ip == "198.51.100.22"
    assert event.host is not None and event.host.name == "auth-srv-01"
    assert event.sentinel.source.provider == "elasticsearch"

    assert len(res.aggregations) == 1
    assert res.aggregations[0].name == "top_users"
    assert res.aggregations[0].buckets[0].key == "admin"
    assert res.aggregations[0].buckets[0].doc_count == 1


@pytest.mark.asyncio
async def test_es_search_shard_failures_honesty(
    mock_es_client: AsyncMock, es_settings: Settings
) -> None:
    mock_es_client.search.return_value = {
        "_shards": {"total": 5, "successful": 4, "failed": 1},
        "hits": {"total": {"value": 0}, "hits": []},
    }
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    res = await provider.search(SearchRequest())

    assert res.metadata.is_partial is True
    assert len(res.metadata.warnings) == 1
    assert "shard(s) failed" in res.metadata.warnings[0]


@pytest.mark.asyncio
async def test_es_search_timeout(mock_es_client: AsyncMock, es_settings: Settings) -> None:
    mock_es_client.search.side_effect = ConnectionTimeout("Request timed out")
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)

    with pytest.raises(TimeoutError, match="timed out"):
        await provider.search(SearchRequest())


@pytest.mark.asyncio
async def test_es_get_field_mappings(mock_es_client: AsyncMock, es_settings: Settings) -> None:
    mock_es_client.indices.get_mapping.return_value = {
        "logs-auth": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "id": {"type": "keyword"},
                        }
                    },
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                        }
                    },
                }
            }
        }
    }
    provider = ElasticsearchProvider(client=mock_es_client, settings=es_settings)
    mappings = await provider.get_field_mappings()

    assert mappings["@timestamp"] == "date"
    assert mappings["user.name"] == "keyword"
    assert mappings["user.id"] == "keyword"
    assert mappings["source.ip"] == "ip"
