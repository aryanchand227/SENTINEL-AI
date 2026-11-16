"""
SENTINEL AI — Chat and Investigation API Schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.query.sqs import SentinelQuerySpec


class ConversationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = "New Investigation"
    provider: str = "synthetic"
    data_mode: str = "synthetic"


class ConversationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    user_id: str
    title: str
    provider: str
    data_mode: str
    created_at: datetime
    updated_at: datetime


class MessageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    role: str
    content: str
    created_at: datetime
    metadata: dict[str, Any] | None = None


class ConversationDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conversation: ConversationResponse
    messages: list[MessageItem] = Field(default_factory=list)


class ChatTurnRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conversation_id: str
    message: str
    investigation_id: str | None = None


class FindingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_type: str
    title: str
    description: str
    classification: str  # observed / inferred / hypothesis
    severity: str
    confidence_label: str
    evidence_ids: list[str] = Field(default_factory=list)


class ChatTurnResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str
    conversation_id: str
    investigation_id: str
    assistant_message: str
    query_spec: SentinelQuerySpec | None = None
    validation_status: str  # valid, invalid, not_applicable
    result_count: int = 0
    evidence_ids: list[str] = Field(default_factory=list)
    findings: list[FindingItem] = Field(default_factory=list)
    data_mode: str = "synthetic"
    follow_up_suggestions: list[str] = Field(default_factory=list)
