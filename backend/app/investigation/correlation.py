"""
SENTINEL AI — Deterministic Investigation Correlation Engine.

Implements explicit entity and temporal correlation patterns (Section 10).
Never relies on unconstrained LLM speculation.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from backend.app.domain.events import EventCategory, EventOutcome, SecurityEvent
from pydantic import BaseModel, ConfigDict, Field


class Correlation(BaseModel):
    """Deterministic correlation finding."""

    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    rule_id: str
    rule_version: str = "1.0.0"
    related_evidence_ids: list[str] = Field(default_factory=list)
    entities_involved: list[str] = Field(default_factory=list)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    observed_relationship: str
    rationale: str
    confidence_label: str  # "high", "medium", "low"
    alternative_explanations: list[str] = Field(default_factory=list)
    status: str = "candidate"  # "candidate", "analyst_reviewed", "dismissed"


class CorrelationEngine:
    """
    Applies deterministic correlation rules over a sequence of security events.
    """

    @classmethod
    def correlate(cls, events: Sequence[SecurityEvent]) -> list[Correlation]:
        if not events:
            return []

        correlations: list[Correlation] = []

        # Sort events chronologically for temporal evaluation
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Pattern 1: Repeated failures followed by success (same user or same IP)
        corr_1 = cls._check_failures_then_success(sorted_events)
        if corr_1:
            correlations.append(corr_1)

        # Pattern 2: Multiple accounts targeted by single source IP
        corr_2 = cls._check_multi_account_spray(sorted_events)
        if corr_2:
            correlations.append(corr_2)

        # Pattern 3: One account authenticating from multiple IPs
        corr_3 = cls._check_account_multi_ip(sorted_events)
        if corr_3:
            correlations.append(corr_3)

        # Pattern 4: Suspicious process execution after authentication on same host
        corr_4 = cls._check_process_after_auth(sorted_events)
        if corr_4:
            correlations.append(corr_4)

        return correlations

    @classmethod
    def _check_failures_then_success(cls, events: Sequence[SecurityEvent]) -> Correlation | None:
        """Rule CORR_001: Repeated authentication failures followed by success."""
        failures: list[SecurityEvent] = []
        successes: list[SecurityEvent] = []

        for ev in events:
            if ev.event.category == EventCategory.AUTHENTICATION:
                if ev.event.outcome == EventOutcome.FAILURE:
                    failures.append(ev)
                elif ev.event.outcome == EventOutcome.SUCCESS:
                    successes.append(ev)

        if len(failures) >= 2 and len(successes) >= 1:
            # Check if any success happened AFTER a failure
            last_fail_time = max(f.timestamp for f in failures)
            qualifying_successes = [s for s in successes if s.timestamp >= last_fail_time]

            if qualifying_successes:
                entities: set[str] = set()
                evidence_ids: list[str] = [f.event.id for f in failures]
                for s in qualifying_successes:
                    evidence_ids.append(s.event.id)

                for ev in failures + qualifying_successes:
                    if ev.user and ev.user.name:
                        entities.add(f"user:{ev.user.name}")
                    if ev.source and ev.source.ip:
                        entities.add(f"ip:{ev.source.ip}")

                return Correlation(
                    correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
                    rule_id="CORR_001_AUTH_BRUTE_FORCE_SUCCESS",
                    rule_version="1.0.0",
                    related_evidence_ids=evidence_ids,
                    entities_involved=sorted(entities),
                    time_window_start=failures[0].timestamp,
                    time_window_end=qualifying_successes[-1].timestamp,
                    observed_relationship=(
                        f"{len(failures)} failed authentication attempts were followed by "
                        f"{len(qualifying_successes)} successful logon(s)."
                    ),
                    rationale=(
                        "A cluster of authentication failures followed immediately by a successful "
                        "logon is consistent with credential guessing or password brute forcing."
                    ),
                    confidence_label="high",
                    alternative_explanations=[
                        "User mistyped password multiple times before entering the correct one.",
                        "Automated script or service entered stale credentials prior to update.",
                    ],
                    status="candidate",
                )
        return None

    @classmethod
    def _check_multi_account_spray(cls, events: Sequence[SecurityEvent]) -> Correlation | None:
        """Rule CORR_002: Multiple accounts targeted by single source IP."""
        ip_accounts: dict[str, set[str]] = defaultdict(set)
        ip_events: dict[str, list[str]] = defaultdict(list)

        for ev in events:
            if (
                ev.event.category == EventCategory.AUTHENTICATION
                and ev.source
                and ev.source.ip
                and ev.user
                and ev.user.name
            ):
                ip_accounts[ev.source.ip].add(ev.user.name)
                ip_events[ev.source.ip].append(ev.event.id)

        for ip, accounts in ip_accounts.items():
            if len(accounts) >= 2:
                entities = [f"ip:{ip}"] + [f"user:{acc}" for acc in sorted(accounts)]
                return Correlation(
                    correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
                    rule_id="CORR_002_MULTI_ACCOUNT_TARGETING",
                    rule_version="1.0.0",
                    related_evidence_ids=ip_events[ip],
                    entities_involved=entities,
                    time_window_start=events[0].timestamp,
                    time_window_end=events[-1].timestamp,
                    observed_relationship=(
                        f"Source IP {ip} targeted {len(accounts)} distinct accounts: "
                        f"{', '.join(sorted(accounts))}."
                    ),
                    rationale=(
                        "Single origin IP attempting authentication across multiple usernames "
                        "indicates potential credential spraying or dictionary scanning."
                    ),
                    confidence_label="high" if len(accounts) >= 3 else "medium",
                    alternative_explanations=[
                        "Shared corporate proxy or NAT gateway with multiple users authenticating.",
                        "Authorized internal vulnerability assessment or penetration test.",
                    ],
                    status="candidate",
                )
        return None

    @classmethod
    def _check_account_multi_ip(cls, events: Sequence[SecurityEvent]) -> Correlation | None:
        """Rule CORR_003: Single account authenticating from multiple unusual source IPs."""
        user_ips: dict[str, set[str]] = defaultdict(set)
        user_events: dict[str, list[str]] = defaultdict(list)

        for ev in events:
            if (
                ev.event.category == EventCategory.AUTHENTICATION
                and ev.event.outcome == EventOutcome.SUCCESS
                and ev.source
                and ev.source.ip
                and ev.user
                and ev.user.name
            ):
                user_ips[ev.user.name].add(ev.source.ip)
                user_events[ev.user.name].append(ev.event.id)

        for user, ips in user_ips.items():
            if len(ips) >= 2:
                entities = [f"user:{user}"] + [f"ip:{ip}" for ip in sorted(ips)]
                return Correlation(
                    correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
                    rule_id="CORR_003_ACCOUNT_MULTI_ORIGIN",
                    rule_version="1.0.0",
                    related_evidence_ids=user_events[user],
                    entities_involved=entities,
                    time_window_start=events[0].timestamp,
                    time_window_end=events[-1].timestamp,
                    observed_relationship=(
                        f"User '{user}' successfully logged in from {len(ips)} distinct "
                        f"IP addresses: {', '.join(sorted(ips))}."
                    ),
                    rationale=(
                        "Concurrent or rapid logins for a single account from different IP ranges "
                        "may indicate credential theft or compromised session tokens."
                    ),
                    confidence_label="medium",
                    alternative_explanations=[
                        "User disconnected from VPN or switched from cellular to WiFi connection.",
                        "Legitimate multi-device usage by the same user.",
                    ],
                    status="candidate",
                )
        return None

    @classmethod
    def _check_process_after_auth(cls, events: Sequence[SecurityEvent]) -> Correlation | None:
        """Rule CORR_004: Suspicious process execution after authentication."""
        auth_successes: list[SecurityEvent] = []
        process_events: list[SecurityEvent] = []

        for ev in events:
            if (
                ev.event.category == EventCategory.AUTHENTICATION
                and ev.event.outcome == EventOutcome.SUCCESS
            ):
                auth_successes.append(ev)
            elif ev.event.category == EventCategory.PROCESS:
                process_events.append(ev)

        for auth in auth_successes:
            auth_host = auth.host.name if auth.host else None
            for proc in process_events:
                proc_host = proc.host.name if proc.host else None
                if (
                    auth_host
                    and proc_host
                    and auth_host == proc_host
                    and proc.timestamp >= auth.timestamp
                ):
                    entities = [f"host:{auth_host}"]
                    if auth.user and auth.user.name:
                        entities.append(f"user:{auth.user.name}")
                    return Correlation(
                        correlation_id=f"corr-{uuid.uuid4().hex[:8]}",
                        rule_id="CORR_004_AUTH_TO_PROCESS_EXEC",
                        rule_version="1.0.0",
                        related_evidence_ids=[auth.event.id, proc.event.id],
                        entities_involved=entities,
                        time_window_start=auth.timestamp,
                        time_window_end=proc.timestamp,
                        observed_relationship=(
                            f"Host '{auth_host}' had process execution after successful logon."
                        ),
                        rationale=(
                            "Process creation following logon is standard administrative "
                            "behavior but can also indicate initial execution or lateral movement."
                        ),
                        confidence_label="medium",
                        alternative_explanations=[
                            "Standard system logon script or administrative session.",
                        ],
                        status="candidate",
                    )
        return None
