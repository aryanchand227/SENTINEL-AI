"""
SENTINEL AI — Typed application settings.

All configuration is loaded from environment variables or .env file.
Secrets are never logged or exposed via API responses.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class SiemProvider(str, Enum):
    SYNTHETIC = "synthetic"
    ELASTICSEARCH = "elasticsearch"
    WAZUH = "wazuh"


class DataMode(str, Enum):
    SYNTHETIC = "synthetic"
    LIVE = "live"


class Settings(BaseSettings):
    """Typed, validated application settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: AppEnv = AppEnv.DEVELOPMENT
    app_name: str = "SENTINEL_AI"
    api_v1_prefix: str = "/api/v1"
    app_secret_key: str = "replace_with_local_random_secret"
    jwt_secret_key: str = "replace_with_local_random_secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    cors_origins: str = "http://localhost:5173"

    # --- Database ---
    database_url: str = "sqlite+aiosqlite:///./sentinel_dev.db"

    # --- SIEM Provider ---
    siem_provider: SiemProvider = SiemProvider.SYNTHETIC
    sentinel_data_mode: DataMode = DataMode.SYNTHETIC

    # --- Elasticsearch ---
    elasticsearch_url: str = "https://localhost:9200"
    elasticsearch_api_key: str = ""
    elasticsearch_username: str = ""
    elasticsearch_password: str = ""
    elasticsearch_index_allowlist: str = "logs-*,wazuh-alerts-*"

    # --- Wazuh ---
    wazuh_api_url: str = "https://wazuh-manager"
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""
    wazuh_api_version: str = ""

    # --- LLM ---
    llm_provider: str = "cloud"
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: int = 30
    llm_max_retries: int = 2

    # --- Query Safety ---
    max_query_window_hours: int = 168
    max_query_page_size: int = 500
    max_aggregation_buckets: int = 100
    query_timeout_seconds: int = 30

    # --- Reports ---
    report_storage_path: Path = Path("./artifacts")
    app_log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def elasticsearch_index_patterns(self) -> list[str]:
        return [
            p.strip()
            for p in self.elasticsearch_index_allowlist.split(",")
            if p.strip()
        ]

    @field_validator("app_secret_key", "jwt_secret_key")
    @classmethod
    def warn_default_secrets(cls, v: str) -> str:
        return v

    def is_synthetic_mode(self) -> bool:
        return self.siem_provider == SiemProvider.SYNTHETIC

    def requires_elasticsearch(self) -> bool:
        return self.siem_provider == SiemProvider.ELASTICSEARCH

    def requires_wazuh(self) -> bool:
        return self.siem_provider == SiemProvider.WAZUH


@lru_cache
def get_settings() -> Settings:
    """Factory for application settings. Cached per process."""
    return Settings()
