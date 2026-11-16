"""
SENTINEL AI — SIEM Provider Registry.

Factory and lifecycle registry for SIEM provider adapters:
- Synthetic (deterministic in-memory security data)
- Elasticsearch (live 8.x read-only cluster)
- Wazuh (live manager REST API)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from backend.app.core.config import Settings, SiemProvider, get_settings
from backend.app.siem.provider_interface import ProviderInterface

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """Registry managing instantiated SIEM providers."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._instances: dict[str, ProviderInterface] = {}

    def get_provider(self, name: str | SiemProvider | None = None) -> ProviderInterface:
        """
        Return an instance of the requested provider.
        If no name is passed, the configured default in Settings.siem_provider is used.
        """
        if name is None:
            provider_name = self._settings.siem_provider.value.lower()
        elif isinstance(name, SiemProvider):
            provider_name = name.value.lower()
        else:
            provider_name = name.lower()

        if provider_name in self._instances:
            return self._instances[provider_name]

        if provider_name == SiemProvider.SYNTHETIC.value:
            from backend.app.siem.synthetic.provider import SyntheticProvider

            provider: ProviderInterface = SyntheticProvider(seed=42)
        elif provider_name == SiemProvider.ELASTICSEARCH.value:
            from backend.app.siem.elasticsearch.adapter import ElasticsearchProvider

            provider = ElasticsearchProvider(settings=self._settings)
        elif provider_name == SiemProvider.WAZUH.value:
            from backend.app.siem.wazuh.adapter import WazuhProvider

            provider = WazuhProvider(settings=self._settings)
        else:
            raise ValueError(f"Unknown SIEM provider: '{provider_name}'")

        self._instances[provider_name] = provider
        return provider

    def register_provider(self, name: str, provider: ProviderInterface) -> None:
        """Register a custom or mock provider instance."""
        self._instances[name.lower()] = provider

    async def close_all(self) -> None:
        """Close any open client connections."""
        for p_name, provider in list(self._instances.items()):
            try:
                await provider.close()
            except Exception as e:
                logger.warning("Error closing provider %s: %s", p_name, e)
        self._instances.clear()


_global_registry: ProviderRegistry | None = None


def get_provider_registry(settings: Settings | None = None) -> ProviderRegistry:
    """Return singleton provider registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ProviderRegistry(settings)
    return _global_registry
