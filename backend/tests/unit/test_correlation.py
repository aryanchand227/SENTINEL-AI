"""
Unit tests for Deterministic Correlation Engine.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.app.domain.events import (
    DataMode,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    HostFields,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    SourceFields,
    UserFields,
)
from backend.app.investigation.correlation import CorrelationEngine


def _make_event(
    ev_id: str,
    category: EventCategory,
    outcome: EventOutcome,
    user: str,
    ip: str,
    host: str,
    ts: datetime,
) -> SecurityEvent:
    return SecurityEvent(
        **{"@timestamp": ts},
        event=EventFields(
            id=ev_id,
            kind=EventKind.EVENT,
            category=category,
            outcome=outcome,
            severity=50,
            created=ts,
        ),
        user=UserFields(name=user),
        source=SourceFields(ip=ip),
        host=HostFields(name=host),
        sentinel=SentinelMetadata(
            source=SentinelSource(provider="synthetic", index="test", document_id=ev_id),
            data_mode=DataMode.SYNTHETIC,
        ),
    )


def test_correlation_empty_events() -> None:
    assert CorrelationEngine.correlate([]) == []


def test_correlation_failures_followed_by_success() -> None:
    base = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
    events = [
        _make_event(
            "e1",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            "admin",
            "192.168.1.100",
            "srv-01",
            base,
        ),
        _make_event(
            "e2",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            "admin",
            "192.168.1.100",
            "srv-01",
            base + timedelta(minutes=1),
        ),
        _make_event(
            "e3",
            EventCategory.AUTHENTICATION,
            EventOutcome.SUCCESS,
            "admin",
            "192.168.1.100",
            "srv-01",
            base + timedelta(minutes=2),
        ),
    ]
    corrs = CorrelationEngine.correlate(events)
    corr_ids = {c.rule_id for c in corrs}
    assert "CORR_001_AUTH_BRUTE_FORCE_SUCCESS" in corr_ids
    c1 = next(c for c in corrs if c.rule_id == "CORR_001_AUTH_BRUTE_FORCE_SUCCESS")
    assert c1.confidence_label == "high"
    assert "e1" in c1.related_evidence_ids
    assert "e2" in c1.related_evidence_ids
    assert "e3" in c1.related_evidence_ids
    assert "user:admin" in c1.entities_involved


def test_correlation_multi_account_spray() -> None:
    base = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
    events = [
        _make_event(
            "e1",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            "alice",
            "10.0.0.99",
            "srv-01",
            base,
        ),
        _make_event(
            "e2",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            "bob",
            "10.0.0.99",
            "srv-01",
            base + timedelta(seconds=10),
        ),
        _make_event(
            "e3",
            EventCategory.AUTHENTICATION,
            EventOutcome.FAILURE,
            "charlie",
            "10.0.0.99",
            "srv-01",
            base + timedelta(seconds=20),
        ),
    ]
    corrs = CorrelationEngine.correlate(events)
    corr_ids = {c.rule_id for c in corrs}
    assert "CORR_002_MULTI_ACCOUNT_TARGETING" in corr_ids
    c2 = next(c for c in corrs if c.rule_id == "CORR_002_MULTI_ACCOUNT_TARGETING")
    assert c2.confidence_label == "high"
    assert "ip:10.0.0.99" in c2.entities_involved
    assert "user:alice" in c2.entities_involved


def test_correlation_account_multi_ip() -> None:
    base = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
    events = [
        _make_event(
            "e1",
            EventCategory.AUTHENTICATION,
            EventOutcome.SUCCESS,
            "dave",
            "198.51.100.1",
            "srv-01",
            base,
        ),
        _make_event(
            "e2",
            EventCategory.AUTHENTICATION,
            EventOutcome.SUCCESS,
            "dave",
            "203.0.113.5",
            "srv-01",
            base + timedelta(minutes=5),
        ),
    ]
    corrs = CorrelationEngine.correlate(events)
    corr_ids = {c.rule_id for c in corrs}
    assert "CORR_003_ACCOUNT_MULTI_ORIGIN" in corr_ids


def test_correlation_process_after_auth() -> None:
    base = datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC)
    events = [
        _make_event(
            "e1",
            EventCategory.AUTHENTICATION,
            EventOutcome.SUCCESS,
            "root",
            "192.168.1.5",
            "db-host",
            base,
        ),
        _make_event(
            "e2",
            EventCategory.PROCESS,
            EventOutcome.SUCCESS,
            "root",
            "192.168.1.5",
            "db-host",
            base + timedelta(minutes=1),
        ),
    ]
    corrs = CorrelationEngine.correlate(events)
    corr_ids = {c.rule_id for c in corrs}
    assert "CORR_004_AUTH_TO_PROCESS_EXEC" in corr_ids
