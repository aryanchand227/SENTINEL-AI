"""
SENTINEL AI — Provider interface (abstract contract).

All SIEM/data providers (synthetic, Elasticsearch, Wazuh)
implement this interface. Provider results are normalized
into the canonical SecurityEvent model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.domain.events import SecurityEvent


class ProviderStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    AUTH_FAILURE = "auth_failure"


class ProviderHealthResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    status: ProviderStatus
    version: str | None = None
    message: str | None = None
    checked_at: datetime


class SearchRequest(BaseModel):
    """Provider-agnostic search request."""

    model_config = ConfigDict(extra="forbid")

    filters: list[dict[str, Any]] = Field(default_factory=list)
    time_start: datetime | None = None
    time_end: datetime | None = None
    sort_field: str = "@timestamp"
    sort_order: str = "desc"  # "asc" or "desc"
    page_size: int = 100
    cursor: str | None = None
    aggregations: list[dict[str, Any]] = Field(default_factory=list)
    requested_fields: list[str] = Field(default_factory=list)


class SearchResultMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    total_hits: int
    returned_count: int
    took_ms: int
    next_cursor: str | None = None
    provider: str
    is_partial: bool = False
    warnings: list[str] = Field(default_factory=list)


class AggregationBucket(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    doc_count: int
    sub_buckets: list[AggregationBucket] | None = None


class AggregationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    buckets: list[AggregationBucket] = Field(default_factory=list)


class ProviderSearchResult(BaseModel):
    """Result from any provider search — normalized events + metadata."""

    model_config = ConfigDict(extra="forbid")

    events: list[SecurityEvent] = Field(default_factory=list)
    metadata: SearchResultMetadata
    aggregations: list[AggregationResult] = Field(default_factory=list)


class ProviderInterface(ABC):
    """Abstract contract all SIEM/data providers must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier: 'synthetic', 'elasticsearch', 'wazuh'."""
        ...

    @abstractmethod
    async def health_check(self) -> ProviderHealthResult:
        """Check provider connectivity and health."""
        ...

    @abstractmethod
    async def search(self, request: SearchRequest) -> ProviderSearchResult:
        """Execute a validated, read-only search and return normalized results."""
        ...

    @abstractmethod
    async def get_field_mappings(self) -> dict[str, str]:
        """Return field name → field type mappings for the provider."""
        ...
