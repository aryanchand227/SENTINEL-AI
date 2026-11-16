"""
Integration tests for database models and session management.
"""

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.persistence.database import Base
from backend.app.persistence.models import (
    AuditEvent,
    Conversation,
    EvidenceReference,
    Finding,
    Investigation,
    Message,
    QueryExecution,
    Report,
    User,
)


@pytest.fixture
async def db_session() -> AsyncSession:
    """In-memory SQLite async test database fixture."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        yield session

    await engine.dispose()


class TestDatabasePersistence:
    @pytest.mark.asyncio
    async def test_create_user_and_conversation(self, db_session: AsyncSession) -> None:
        user = User(
            email="analyst@sentinel.ai",
            password_hash="$2b$12$fakehashplaceholder",
            display_name="SOC Analyst",
            role="analyst",
        )
        db_session.add(user)
        await db_session.flush()

        conv = Conversation(
            user_id=user.id,
            title="Brute Force Investigation",
            provider="synthetic",
            data_mode="synthetic",
        )
        db_session.add(conv)
        await db_session.flush()

        msg = Message(
            conversation_id=conv.id,
            role="user",
            content="Show failed SSH logins in the last 24 hours.",
            request_id="req-001",
        )
        db_session.add(msg)
        await db_session.commit()

        # Query back and verify relations
        result = await db_session.execute(select(User).where(User.email == "analyst@sentinel.ai"))
        saved_user = result.scalar_one()
        assert saved_user.display_name == "SOC Analyst"
        assert saved_user.is_active is True

        conv_result = await db_session.execute(
            select(Conversation).where(Conversation.user_id == user.id)
        )
        saved_conv = conv_result.scalar_one()
        assert saved_conv.title == "Brute Force Investigation"

    @pytest.mark.asyncio
    async def test_investigation_and_evidence_flow(self, db_session: AsyncSession) -> None:
        # User
        user = User(
            email="lead@sentinel.ai",
            password_hash="hash",
            display_name="Lead Analyst",
            role="senior_analyst",
        )
        db_session.add(user)
        await db_session.flush()

        # Investigation
        inv = Investigation(
            user_id=user.id,
            status="open",
            provider="synthetic",
            data_mode="synthetic",
            summary="Investigating 20 failed SSH logins",
            risk_level="high",
            risk_score=75,
        )
        db_session.add(inv)
        await db_session.flush()

        # Query execution
        qexec = QueryExecution(
            investigation_id=inv.id,
            provider="synthetic",
            query_spec={"intent": "Find SSH failures", "filters": []},
            validation_status="valid",
            execution_status="success",
            result_count=20,
            duration_ms=15,
        )
        db_session.add(qexec)

        # Evidence reference
        ev = EvidenceReference(
            investigation_id=inv.id,
            provider="synthetic",
            event_id="evt-cd0f1f220c61235f",
            event_timestamp=datetime(2026, 11, 15, 1, 0, tzinfo=UTC),
            snapshot={"action": "ssh_login", "outcome": "failure"},
        )
        db_session.add(ev)

        # Finding
        finding = Finding(
            investigation_id=inv.id,
            finding_type="ssh_brute_force",
            title="SSH Brute Force Detected",
            description="20 failed login attempts from 192.168.1.100 targeting root user",
            classification="observed",
            severity="high",
            confidence_label="high",
            evidence_ids=[ev.event_id],
        )
        db_session.add(finding)

        # Report
        report = Report(
            investigation_id=inv.id,
            user_id=user.id,
            format="pdf",
            status="completed",
            data_mode="synthetic",
            artifact_path="./artifacts/report-001.pdf",
            sha256="abc123hash",
        )
        db_session.add(report)

        # Audit Event
        audit = AuditEvent(
            user_id=user.id,
            action="report_generation",
            resource_type="report",
            resource_id=report.id,
            outcome="success",
        )
        db_session.add(audit)

        await db_session.commit()

        # Verification
        inv_check = (
            await db_session.execute(select(Investigation).where(Investigation.id == inv.id))
        ).scalar_one()
        assert inv_check.risk_level == "high"
        assert inv_check.risk_score == 75

        findings = (
            (await db_session.execute(select(Finding).where(Finding.investigation_id == inv.id)))
            .scalars()
            .all()
        )
        assert len(findings) == 1
        assert findings[0].classification == "observed"
        assert findings[0].evidence_ids == ["evt-cd0f1f220c61235f"]
