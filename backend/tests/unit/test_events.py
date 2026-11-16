"""
Unit tests for canonical event model and synthetic event generator.
"""

from datetime import UTC, datetime

import pytest

from backend.app.domain.events import (
    DataMode,
    EventCategory,
    EventOutcome,
    SecurityEvent,
)
from backend.app.siem.synthetic.generator import SyntheticEventGenerator


class TestSecurityEvent:
    """Test the canonical SecurityEvent model."""

    def test_minimal_event_creation(self) -> None:
        """Can create a valid event with minimum required fields."""
        from backend.app.domain.events import (
            EventFields,
            SentinelMetadata,
            SentinelSource,
        )

        event = SecurityEvent(
            **{"@timestamp": datetime(2026, 1, 1, tzinfo=UTC)},
            event=EventFields(
                id="test-001",
                category=EventCategory.AUTHENTICATION,
            ),
            sentinel=SentinelMetadata(
                source=SentinelSource(provider="synthetic"),
                data_mode=DataMode.SYNTHETIC,
            ),
        )
        assert event.event.id == "test-001"
        assert event.event.category == EventCategory.AUTHENTICATION
        assert event.sentinel.data_mode == DataMode.SYNTHETIC

    def test_event_extra_fields_forbidden(self) -> None:
        """Extra fields are rejected (strict model)."""
        from backend.app.domain.events import EventFields

        with pytest.raises(Exception):  # ValidationError
            EventFields(
                id="test-002",
                category=EventCategory.AUTHENTICATION,
                bogus_field="should_fail",  # type: ignore[call-arg]
            )


class TestSyntheticEventGenerator:
    """Test deterministic synthetic event generation."""

    def test_generate_all_returns_events(self) -> None:
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        assert len(events) > 0
        assert all(isinstance(e, SecurityEvent) for e in events)

    def test_reproducibility(self) -> None:
        """Same seed produces identical events."""
        gen1 = SyntheticEventGenerator(seed=42)
        gen2 = SyntheticEventGenerator(seed=42)
        events1 = gen1.generate_all()
        events2 = gen2.generate_all()
        assert len(events1) == len(events2)
        for e1, e2 in zip(events1, events2):
            assert e1.event.id == e2.event.id
            assert e1.timestamp == e2.timestamp

    def test_different_seed_different_events(self) -> None:
        """Different seeds produce different port assignments."""
        gen1 = SyntheticEventGenerator(seed=42)
        gen2 = SyntheticEventGenerator(seed=99)
        events1 = gen1.generate_all()
        events2 = gen2.generate_all()
        # Same structure but source ports should differ (randomized)
        ports1 = [e.source.port for e in events1 if e.source and e.source.port]
        ports2 = [e.source.port for e in events2 if e.source and e.source.port]
        assert ports1 != ports2

    def test_idempotent_generation(self) -> None:
        """Calling generate_all twice returns cached results."""
        gen = SyntheticEventGenerator(seed=42)
        events1 = gen.generate_all()
        events2 = gen.generate_all()
        assert events1 is events2

    def test_all_scenarios_covered(self) -> None:
        """Events cover all major categories."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        categories = {e.event.category for e in events}
        assert EventCategory.AUTHENTICATION in categories
        assert EventCategory.PROCESS in categories
        assert EventCategory.FILE in categories
        assert EventCategory.NETWORK in categories
        assert EventCategory.IAM in categories
        assert EventCategory.MALWARE in categories

    def test_all_events_synthetic_mode(self) -> None:
        """Every event is marked as synthetic."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        for e in events:
            assert e.sentinel.data_mode == DataMode.SYNTHETIC

    def test_stable_event_ids(self) -> None:
        """Event IDs are deterministic across runs."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        ids = [e.event.id for e in events]
        assert len(ids) == len(set(ids)), "All event IDs must be unique"
        # Verify they follow the expected format
        for eid in ids:
            assert eid.startswith("evt-")

    def test_ssh_brute_force_events(self) -> None:
        """Scenario 1: 20 failed SSH logins from attacker IP."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        ssh_failures = [
            e for e in events
            if e.event.action == "ssh_login"
            and e.event.outcome == EventOutcome.FAILURE
            and e.source and e.source.ip == "192.168.1.100"
        ]
        assert len(ssh_failures) == 20

    def test_brute_force_then_success(self) -> None:
        """Scenario 2: Failed SSH logins followed by success."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        s2_fails = [
            e for e in events
            if e.event.action == "ssh_login"
            and e.event.outcome == EventOutcome.FAILURE
            and e.source and e.source.ip == "10.0.0.55"
        ]
        s2_success = [
            e for e in events
            if e.event.action == "ssh_login"
            and e.event.outcome == EventOutcome.SUCCESS
            and e.source and e.source.ip == "10.0.0.55"
        ]
        assert len(s2_fails) == 15
        assert len(s2_success) == 1

    def test_benign_events_exist(self) -> None:
        """Scenario 10: Benign activity should not be escalated."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        benign = [
            e for e in events
            if e.event.severity == 0  # INFORMATIONAL
        ]
        assert len(benign) >= 3  # at least 3 benign logins + routine tasks

    def test_event_count_total(self) -> None:
        """Total event count matches expected scenarios."""
        gen = SyntheticEventGenerator(seed=42)
        events = gen.generate_all()
        # S1: 20, S2: 16, S3: 30, S4: 3, S5: 2, S6: 3, S7: 11, S8: 3, S9: 1, S10: 5
        assert len(events) == 94
