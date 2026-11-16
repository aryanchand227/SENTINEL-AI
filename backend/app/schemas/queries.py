"""
SENTINEL AI — Query API Schemas.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.query.sqs import SentinelQuerySpec
from backend.app.query.validator import ValidationErrorDetail
from backend.app.siem.provider_interface import AggregationResult, SearchResultMetadata


class QueryPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: SentinelQuerySpec


class QueryPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_valid: bool
    errors: list[ValidationErrorDetail] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    compiled_request: dict[str, Any] | None = None
    provider: str
    data_mode: str


class QueryExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: SentinelQuerySpec
    investigation_id: str | None = None


class QueryExecuteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_id: str
    provider: str
    data_mode: str
    metadata: SearchResultMetadata
    events: list[dict[str, Any]] = Field(default_factory=list)
    aggregations: list[AggregationResult] = Field(default_factory=list)
