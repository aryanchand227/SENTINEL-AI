"""
Verification script for Supabase PostgreSQL database connectivity and ORM operations.
"""

from __future__ import annotations

import asyncio
import os

from backend.app.persistence.models import Conversation, User
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./sentinel_dev.db",
)


async def verify_db() -> None:
    host_part = DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL
    print(f"Connecting to: {host_part}")
    engine = create_async_engine(DATABASE_URL)
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        # 1. Query table listing
        query = text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' ORDER BY table_name;"
        )
        res = await session.execute(query)
        tables = [row[0] for row in res.fetchall()]
        print("Tables in Supabase public schema:", tables)
        expected = [
            "alembic_version",
            "audit_events",
            "conversations",
            "evidence_references",
            "findings",
            "investigations",
            "messages",
            "query_executions",
            "reports",
            "users",
        ]
        for t in expected:
            assert t in tables, f"Missing table: {t}"
        print(f"Verified all {len(expected)} expected tables exist!")

        # 2. Test Write/Read using SQLAlchemy ORM models
        test_email = "verify_supabase@sentinel.ai"
        user = User(
            email=test_email,
            password_hash="dummy_hash_for_test",
            display_name="Verification User",
            role="analyst",
        )
        session.add(user)
        await session.flush()
        print(f"Successfully inserted test user: ID={user.id}")

        conv = Conversation(
            user_id=user.id,
            title="Supabase Connectivity Test Conversation",
            provider="synthetic",
            data_mode="synthetic",
        )
        session.add(conv)
        await session.flush()
        print(f"Successfully inserted test conversation: ID={conv.id}")

        # 3. Read back records
        read_user = (
            await session.execute(select(User).where(User.email == test_email))
        ).scalar_one()
        assert read_user.display_name == "Verification User"
        print(
            f"Successfully read back test user: {read_user.email} (Role: {read_user.role})"
        )

        # 4. Clean up
        await session.delete(conv)
        await session.delete(user)
        await session.commit()
        print("Cleaned up test records.")

    await engine.dispose()
    print("\n>>> ALL SUPABASE CONNECTIVITY & ORM READ/WRITE TESTS PASSED! <<<")


if __name__ == "__main__":
    asyncio.run(verify_db())
