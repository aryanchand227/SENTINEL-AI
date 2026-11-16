"""
Unit tests for Provider Registry.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from backend.app.core.config import Settings, SiemProvider
from backend.app.siem.elasticsearch.adapter import ElasticsearchProvider
from backend.app.siem.provider_interface import ProviderInterface
from backend.app.siem.registry import ProviderRegistry
from backend.app.siem.synthetic.provider import SyntheticProvider
from backend.app.siem.wazuh.adapter import WazuhProvider


def test_registry_resolves_synthetic() -> None:
    settings = Settings(siem_provider=SiemProvider.SYNTHETIC)
    registry = ProviderRegistry(settings)
    provider = registry.get_provider()
    assert isinstance(provider, SyntheticProvider)
    assert provider.name == "synthetic"


def test_registry_resolves_elasticsearch() -> None:
    settings = Settings(siem_provider=SiemProvider.ELASTICSEARCH)
    registry = ProviderRegistry(settings)
    provider = registry.get_provider("elasticsearch")
    assert isinstance(provider, ElasticsearchProvider)
    assert provider.name == "elasticsearch"


def test_registry_resolves_wazuh() -> None:
    settings = Settings(siem_provider=SiemProvider.WAZUH)
    registry = ProviderRegistry(settings)
    provider = registry.get_provider("wazuh")
    assert isinstance(provider, WazuhProvider)
    assert provider.name == "wazuh"


def test_registry_unknown_provider_raises() -> None:
    registry = ProviderRegistry()
    with pytest.raises(ValueError, match="Unknown SIEM provider"):
        registry.get_provider("splunk")


@pytest.mark.asyncio
async def test_registry_close_all() -> None:
    registry = ProviderRegistry()
    mock_provider = AsyncMock(spec=ProviderInterface)
    registry.register_provider("mock", mock_provider)

    await registry.close_all()
    mock_provider.close.assert_awaited_once()
