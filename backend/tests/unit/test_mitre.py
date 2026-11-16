"""
Unit tests for MITRE ATT&CK Catalog & Behavioral Mapper.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.app.domain.events import (
    DataMode,
    DestinationFields,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    HostFields,
    NetworkFields,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    SourceFields,
    UserFields,
)
from backend.app.investigation.mitre import MITRE_CATALOG, MitreMapper


def _create_event(
    event_id: str,
    category: EventCategory,
    outcome: EventOutcome,
    message: str = "",
    action: str = "",
    user: str = "analyst",
    ip: str = "192.168.1.10",
    transport: str | None = None,
    dst_port: int | None = None,
) -> SecurityEvent:
    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    network = NetworkFields(protocol=transport) if transport else None
    destination = DestinationFields(ip="10.0.0.1", port=dst_port) if dst_port else None
    return SecurityEvent(
        **{"@timestamp": now},
        event=EventFields(
            id=event_id,
            kind=EventKind.EVENT,
            category=category,
            action=action,
            outcome=outcome,
            severity=50,
            created=now,
        ),
        message=message,
        source=SourceFields(ip=ip),
        destination=destination,
        network=network,
        user=UserFields(name=user),
        host=HostFields(name="srv-01"),
        sentinel=SentinelMetadata(
            source=SentinelSource(provider="synthetic", index="test", document_id=event_id),
            data_mode=DataMode.SYNTHETIC,
        ),
    )


def test_mitre_catalog_approved_techniques() -> None:
    assert "T1110.001" in MITRE_CATALOG
    assert "T1078" in MITRE_CATALOG
    assert "T1059.001" in MITRE_CATALOG
    assert "T1021.004" in MITRE_CATALOG
    assert "T1486" in MITRE_CATALOG
    for defn in MITRE_CATALOG.values():
        assert defn.id.startswith("T")
        assert len(defn.name) > 0
        assert len(defn.tactic) > 0


def test_map_brute_force_events() -> None:
    events = [
        _create_event(
            "e1", EventCategory.AUTHENTICATION, EventOutcome.FAILURE, message="Failed password"
        ),
        _create_event(
            "e2", EventCategory.AUTHENTICATION, EventOutcome.FAILURE, message="Failed password"
        ),
        _create_event(
            "e3", EventCategory.AUTHENTICATION, EventOutcome.FAILURE, message="Failed password"
        ),
    ]
    candidates = MitreMapper.map_events(events)
    t_ids = {c.technique_id for c in candidates}
    assert "T1110.001" in t_ids

    # 3 events -> confidence elevated to supported
    brute = next(c for c in candidates if c.technique_id == "T1110.001")
    assert brute.confidence == "supported"
    assert len(brute.evidence_ids) == 3


def test_map_powershell_execution() -> None:
    events = [
        _create_event(
            "e4",
            EventCategory.PROCESS,
            EventOutcome.SUCCESS,
            message="powershell.exe -ExecutionPolicy Bypass -File script.ps1",
            action="process_started",
        ),
    ]
    candidates = MitreMapper.map_events(events)
    t_ids = {c.technique_id for c in candidates}
    assert "T1059.001" in t_ids
    ps = next(c for c in candidates if c.technique_id == "T1059.001")
    assert ps.tactic == "Execution"


def test_map_ssh_lateral_movement() -> None:
    events = [
        _create_event(
            "e5",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            message="sshd[123]: Connection from 10.0.0.5 port 22",
            action="sshd_logon",
            transport="tcp",
            dst_port=22,
        ),
    ]
    candidates = MitreMapper.map_events(events)
    t_ids = {c.technique_id for c in candidates}
    assert "T1021.004" in t_ids
