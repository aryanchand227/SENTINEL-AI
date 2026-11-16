"""
Unit tests for core configuration.
"""

import os

import pytest


class TestSettings:
    """Test typed application settings."""

    def test_default_settings_load(self) -> None:
        """Settings can be instantiated with defaults (no .env needed)."""
        from backend.app.core.config import Settings

        s = Settings(
            _env_file=None,  # type: ignore[call-arg]
        )
        assert s.app_name == "SENTINEL_AI"
        assert s.siem_provider.value == "synthetic"
        assert s.sentinel_data_mode.value == "synthetic"
        assert s.api_v1_prefix == "/api/v1"

    def test_synthetic_mode_detection(self) -> None:
        from backend.app.core.config import Settings

        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.is_synthetic_mode() is True
        assert s.requires_elasticsearch() is False
        assert s.requires_wazuh() is False

    def test_cors_origin_list(self) -> None:
        from backend.app.core.config import Settings

        s = Settings(
            cors_origins="http://localhost:5173, http://localhost:3000",
            _env_file=None,  # type: ignore[call-arg]
        )
        assert s.cors_origin_list == ["http://localhost:5173", "http://localhost:3000"]

    def test_elasticsearch_index_patterns(self) -> None:
        from backend.app.core.config import Settings

        s = Settings(
            elasticsearch_index_allowlist="logs-*,wazuh-alerts-*,custom-*",
            _env_file=None,  # type: ignore[call-arg]
        )
        assert s.elasticsearch_index_patterns == ["logs-*", "wazuh-alerts-*", "custom-*"]

    def test_settings_from_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Settings can be loaded from environment variables."""
        monkeypatch.setenv("SIEM_PROVIDER", "elasticsearch")
        monkeypatch.setenv("SENTINEL_DATA_MODE", "live")
        monkeypatch.setenv("APP_ENV", "production")

        from backend.app.core.config import Settings

        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.siem_provider.value == "elasticsearch"
        assert s.sentinel_data_mode.value == "live"
        assert s.app_env.value == "production"
        assert s.requires_elasticsearch() is True
