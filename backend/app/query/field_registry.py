"""
SENTINEL AI — Field Registry.

Maintains the authoritative catalog of ECS-compatible fields,
their data types, and supported operators.
Enforces query safety by rejecting unknown or incompatible fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from backend.app.query.sqs import FilterOperator


class FieldDataType(StrEnum):
    KEYWORD = "keyword"
    TEXT = "text"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATE = "date"
    IP = "ip"


# Allowed operators by field data type
ALLOWED_OPERATORS: dict[FieldDataType, set[FilterOperator]] = {
    FieldDataType.KEYWORD: {
        FilterOperator.EQ,
        FilterOperator.IN,
        FilterOperator.CONTAINS,
        FilterOperator.EXISTS,
    },
    FieldDataType.TEXT: {
        FilterOperator.CONTAINS,
        FilterOperator.EXISTS,
    },
    FieldDataType.INTEGER: {
        FilterOperator.EQ,
        FilterOperator.IN,
        FilterOperator.GTE,
        FilterOperator.LTE,
        FilterOperator.GT,
        FilterOperator.LT,
        FilterOperator.EXISTS,
    },
    FieldDataType.FLOAT: {
        FilterOperator.EQ,
        FilterOperator.GTE,
        FilterOperator.LTE,
        FilterOperator.GT,
        FilterOperator.LT,
        FilterOperator.EXISTS,
    },
    FieldDataType.BOOLEAN: {
        FilterOperator.EQ,
        FilterOperator.EXISTS,
    },
    FieldDataType.DATE: {
        FilterOperator.EQ,
        FilterOperator.GTE,
        FilterOperator.LTE,
        FilterOperator.GT,
        FilterOperator.LT,
        FilterOperator.EXISTS,
    },
    FieldDataType.IP: {
        FilterOperator.EQ,
        FilterOperator.IN,
        FilterOperator.EXISTS,
    },
}


@dataclass(frozen=True)
class FieldDefinition:
    name: str
    data_type: FieldDataType
    description: str
    aggregatable: bool = True


# Approved canonical security event fields catalog
APPROVED_FIELDS: dict[str, FieldDefinition] = {
    "@timestamp": FieldDefinition(
        name="@timestamp",
        data_type=FieldDataType.DATE,
        description="Event creation or observed timestamp in UTC",
        aggregatable=True,
    ),
    "event.id": FieldDefinition(
        name="event.id",
        data_type=FieldDataType.KEYWORD,
        description="Unique event identifier",
        aggregatable=False,
    ),
    "event.kind": FieldDefinition(
        name="event.kind",
        data_type=FieldDataType.KEYWORD,
        description="High-level category: alert, event, metric, state, signal",
        aggregatable=True,
    ),
    "event.category": FieldDefinition(
        name="event.category",
        data_type=FieldDataType.KEYWORD,
        description="Event category: authentication, network, process, file, etc.",
        aggregatable=True,
    ),
    "event.type": FieldDefinition(
        name="event.type",
        data_type=FieldDataType.KEYWORD,
        description="Sub-category type: start, end, info, connection, etc.",
        aggregatable=True,
    ),
    "event.action": FieldDefinition(
        name="event.action",
        data_type=FieldDataType.KEYWORD,
        description="Specific action captured by the event",
        aggregatable=True,
    ),
    "event.outcome": FieldDefinition(
        name="event.outcome",
        data_type=FieldDataType.KEYWORD,
        description="Result of action: success, failure, unknown",
        aggregatable=True,
    ),
    "event.severity": FieldDefinition(
        name="event.severity",
        data_type=FieldDataType.INTEGER,
        description="Numeric severity: 0 (info), 25 (low), 50 (medium), 75 (high), 100 (critical)",
        aggregatable=True,
    ),
    "message": FieldDefinition(
        name="message",
        data_type=FieldDataType.TEXT,
        description="Human-readable event message or log line",
        aggregatable=False,
    ),
    "source.ip": FieldDefinition(
        name="source.ip",
        data_type=FieldDataType.IP,
        description="Source IP address",
        aggregatable=True,
    ),
    "source.port": FieldDefinition(
        name="source.port",
        data_type=FieldDataType.INTEGER,
        description="Source network port",
        aggregatable=True,
    ),
    "destination.ip": FieldDefinition(
        name="destination.ip",
        data_type=FieldDataType.IP,
        description="Destination IP address",
        aggregatable=True,
    ),
    "destination.port": FieldDefinition(
        name="destination.port",
        data_type=FieldDataType.INTEGER,
        description="Destination network port",
        aggregatable=True,
    ),
    "user.name": FieldDefinition(
        name="user.name",
        data_type=FieldDataType.KEYWORD,
        description="Username associated with event",
        aggregatable=True,
    ),
    "user.id": FieldDefinition(
        name="user.id",
        data_type=FieldDataType.KEYWORD,
        description="Unique user identifier",
        aggregatable=True,
    ),
    "host.name": FieldDefinition(
        name="host.name",
        data_type=FieldDataType.KEYWORD,
        description="Hostname",
        aggregatable=True,
    ),
    "host.id": FieldDefinition(
        name="host.id",
        data_type=FieldDataType.KEYWORD,
        description="Host unique identifier",
        aggregatable=True,
    ),
    "host.os.name": FieldDefinition(
        name="host.os.name",
        data_type=FieldDataType.KEYWORD,
        description="Host operating system name",
        aggregatable=True,
    ),
    "process.name": FieldDefinition(
        name="process.name",
        data_type=FieldDataType.KEYWORD,
        description="Process image or binary name",
        aggregatable=True,
    ),
    "process.command_line": FieldDefinition(
        name="process.command_line",
        data_type=FieldDataType.TEXT,
        description="Full process command line invocation",
        aggregatable=False,
    ),
    "process.pid": FieldDefinition(
        name="process.pid",
        data_type=FieldDataType.INTEGER,
        description="Process ID",
        aggregatable=False,
    ),
    "file.path": FieldDefinition(
        name="file.path",
        data_type=FieldDataType.KEYWORD,
        description="File path",
        aggregatable=True,
    ),
    "file.hash.sha256": FieldDefinition(
        name="file.hash.sha256",
        data_type=FieldDataType.KEYWORD,
        description="File SHA-256 hash",
        aggregatable=True,
    ),
    "rule.id": FieldDefinition(
        name="rule.id",
        data_type=FieldDataType.KEYWORD,
        description="Detection rule identifier",
        aggregatable=True,
    ),
    "rule.name": FieldDefinition(
        name="rule.name",
        data_type=FieldDataType.KEYWORD,
        description="Detection rule human-readable name",
        aggregatable=True,
    ),
    "agent.id": FieldDefinition(
        name="agent.id",
        data_type=FieldDataType.KEYWORD,
        description="Security agent ID",
        aggregatable=True,
    ),
    "agent.name": FieldDefinition(
        name="agent.name",
        data_type=FieldDataType.KEYWORD,
        description="Security agent name",
        aggregatable=True,
    ),
    "network.protocol": FieldDefinition(
        name="network.protocol",
        data_type=FieldDataType.KEYWORD,
        description="Network protocol (tcp, udp, ssh, https, etc.)",
        aggregatable=True,
    ),
    "observer.name": FieldDefinition(
        name="observer.name",
        data_type=FieldDataType.KEYWORD,
        description="Observer / collector agent name",
        aggregatable=True,
    ),
    "sentinel.source.provider": FieldDefinition(
        name="sentinel.source.provider",
        data_type=FieldDataType.KEYWORD,
        description="Source provider (synthetic, elasticsearch, wazuh)",
        aggregatable=True,
    ),
    "sentinel.data_mode": FieldDefinition(
        name="sentinel.data_mode",
        data_type=FieldDataType.KEYWORD,
        description="Data mode (synthetic, live)",
        aggregatable=True,
    ),
}


def get_field_definition(field_name: str) -> FieldDefinition | None:
    """Return field definition if approved, else None."""
    return APPROVED_FIELDS.get(field_name)


def is_field_approved(field_name: str) -> bool:
    """Check if field is in the approved registry."""
    return field_name in APPROVED_FIELDS


def is_operator_allowed(field_name: str, operator: FilterOperator) -> bool:
    """Check if operator is compatible with field data type."""
    field_def = get_field_definition(field_name)
    if not field_def:
        return False
    return operator in ALLOWED_OPERATORS.get(field_def.data_type, set())
