"""
Unit tests for Transparent Risk Assessment Engine.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.app.domain.events import (
    DataMode,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    UserFields,
)
from backend.app.investigation.correlation import Correlation
from backend.app.investigation.mitre import AttackTechniqueCandidate
from backend.app.investigation.risk import RiskEngine


def _make_event(
    ev_id: str, severity: int, outcome: EventOutcome = EventOutcome.FAILURE
) -> SecurityEvent:
    now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    return SecurityEvent(
        **{"@timestamp": now},
        event=EventFields(
            id=ev_id,
            kind=EventKind.EVENT,
            category=EventCategory.AUTHENTICATION,
            outcome=outcome,
            severity=severity,
            created=now,
        ),
        user=UserFields(name="testuser"),
        sentinel=SentinelMetadata(
            source=SentinelSource(provider="synthetic", index="test", document_id=ev_id),
            data_mode=DataMode.SYNTHETIC,
        ),
    )


def test_risk_zero_events() -> None:
    res = RiskEngine.evaluate([])
    assert res.score == 0
    assert res.severity == "informational"
    assert len(res.evidence_ids) == 0


def test_risk_base_event_severity() -> None:
    # Single failure event: 32 pts base minus 10 pts for no verified breach = 22 pts
    fail_events = [_make_event("e1", severity=80, outcome=EventOutcome.FAILURE)]
    fail_res = RiskEngine.evaluate(fail_events)
    assert fail_res.score == 22
    assert fail_res.severity == "low"
    assert "Peak verified event severity" in fail_res.factors_increased[0]
    assert "No successful compromise" in fail_res.factors_reduced[0]

    # Success event: 32 pts base without mitigating deduction
    succ_events = [_make_event("e2", severity=80, outcome=EventOutcome.SUCCESS)]
    succ_res = RiskEngine.evaluate(succ_events)
    assert succ_res.score == 32
    assert succ_res.severity == "low"
    assert "Peak verified event severity" in succ_res.factors_increased[0]


def test_risk_elevated_by_brute_force_success() -> None:
    events = [
        _make_event("e1", severity=75, outcome=EventOutcome.FAILURE),
        _make_event("e2", severity=75, outcome=EventOutcome.SUCCESS),
    ]
    corr = Correlation(
        correlation_id="c1",
        rule_id="CORR_001_AUTH_BRUTE_FORCE_SUCCESS",
        observed_relationship="Failures followed by success",
        rationale="Brute force success",
        confidence_label="high",
        related_evidence_ids=["e1", "e2"],
    )
    res = RiskEngine.evaluate(events, correlations=[corr])
    # 75 * 0.40 = 30 + 25 = 55 -> medium (score 55)
    assert res.score >= 50
    assert "Brute force sequence concluded with successful logon" in " ".join(res.factors_increased)


def test_risk_critical_threshold() -> None:
    events = [
        _make_event("e1", severity=100, outcome=EventOutcome.FAILURE),
        _make_event("e2", severity=100, outcome=EventOutcome.SUCCESS),
    ]
    c1 = Correlation(
        correlation_id="c1",
        rule_id="CORR_001_AUTH_BRUTE_FORCE_SUCCESS",
        observed_relationship="Failures followed by success",
        rationale="Brute force success",
        confidence_label="high",
        related_evidence_ids=["e1", "e2"],
    )
    c2 = Correlation(
        correlation_id="c2",
        rule_id="CORR_002_MULTI_ACCOUNT_TARGETING",
        observed_relationship="Multiple accounts targeted",
        rationale="Spray",
        confidence_label="high",
        related_evidence_ids=["e1", "e2"],
    )
    attack = AttackTechniqueCandidate(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        rationale="Ransomware",
    )
    # 40 (base) + 25 (c1) + 20 (c2) + 15 (impact) = 100
    res = RiskEngine.evaluate(events, correlations=[c1, c2], attack_candidates=[attack])
    assert res.score == 100
    assert res.severity == "critical"
