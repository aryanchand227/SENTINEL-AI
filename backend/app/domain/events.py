"""
SENTINEL AI — Canonical Security Event Model.

ECS-compatible domain model used across all providers.
All timestamps are UTC. Optional fields are modeled correctly.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventKind(StrEnum):
    ALERT = "alert"
    EVENT = "event"
    METRIC = "metric"
    STATE = "state"
    SIGNAL = "signal"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    INTRUSION_DETECTION = "intrusion_detection"
    MALWARE = "malware"
    WEB = "web"
    HOST = "host"
    IAM = "iam"
    CONFIGURATION = "configuration"
    PACKAGE = "package"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventSeverity(int, Enum):
    """Numeric severity on ECS scale: 0=informational, 25=low, 50=medium, 75=high, 100=critical."""

    INFORMATIONAL = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100


class DataMode(StrEnum):
    SYNTHETIC = "synthetic"
    LIVE = "live"


# --- Nested ECS-compatible field groups ---


class SourceFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str | None = None
    port: int | None = None


class DestinationFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str | None = None
    port: int | None = None


class UserFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    id: str | None = None


class HostOS(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None


class HostFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    id: str | None = None
    os: HostOS | None = None


class ProcessFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    command_line: str | None = None
    pid: int | None = None


class FileHash(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sha256: str | None = None


class FileFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str | None = None
    hash: FileHash | None = None


class RuleFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    name: str | None = None


class AgentFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    name: str | None = None


class NetworkFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: str | None = None


class ObserverFields(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None


class SentinelSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    index: str | None = None
    document_id: str | None = None


class SentinelMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: SentinelSource
    data_mode: DataMode
    normalization_version: str = "1.0.0"


class EventFields(BaseModel):
    """Core event descriptor fields."""

    model_config = ConfigDict(extra="forbid")
    id: str
    kind: EventKind = EventKind.EVENT
    category: EventCategory
    type: str | None = None  # e.g. "start", "end", "info", "access", "creation"
    action: str | None = None
    outcome: EventOutcome | None = None
    severity: int = EventSeverity.INFORMATIONAL
    created: datetime | None = None
    ingested: datetime | None = None


class SecurityEvent(BaseModel):
    """
    Canonical security event — the single event model used across all providers.

    ECS-compatible field names. Optional fields modeled correctly.
    Preserves source provenance via sentinel metadata.
    """

    model_config = ConfigDict(extra="forbid")

    event: EventFields
    timestamp: datetime = Field(alias="@timestamp")
    message: str | None = None

    source: SourceFields | None = None
    destination: DestinationFields | None = None
    user: UserFields | None = None
    host: HostFields | None = None
    process: ProcessFields | None = None
    file: FileFields | None = None
    rule: RuleFields | None = None
    agent: AgentFields | None = None
    network: NetworkFields | None = None
    observer: ObserverFields | None = None

    sentinel: SentinelMetadata

    # Original source payload for forensic traceability (access-controlled)
    raw_source: dict[str, Any] | None = Field(default=None, exclude=True)
