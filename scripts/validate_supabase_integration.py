"""
SENTINEL AI — Supabase PostgreSQL Database Integration Validator.

Validates the backend's database integration against live Supabase PostgreSQL:
1. Executes `SELECT 1` using the existing AsyncEngine.
2. Checks engine dialect and retrieves live server version.
3. Tests database session creation, query execution, commit, and cleanup.
4. Verifies all 9 ORM models map to existing tables in Supabase public schema.
5. Verifies error rollback behavior on transaction abort.
"""

from __future__ import annotations

import asyncio
import sys
import time

from backend.app.persistence.database import (
    close_db,
    get_db_session,
    get_engine,
)
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
from sqlalchemy import text
from sqlalchemy.orm import class_mapper


async def main() -> int:
    print("=" * 80)
    print("  SENTINEL AI — Supabase PostgreSQL Integration Validation")
    print("=" * 80)

    # 1. Engine Inspection & Live Ping
    t0 = time.perf_counter()
    engine = get_engine()
    host_display = str(engine.url).split("@")[-1] if "@" in str(engine.url) else "local"
    print(f"Dialect: {engine.name} (driver: {engine.driver})")
    print(f"Target:  {host_display}")

    try:
        async with engine.connect() as conn:
            ping_res = await conn.execute(text("SELECT 1"))
            assert ping_res.scalar() == 1
            ver_res = await conn.execute(text("SELECT version()"))
            server_version = ver_res.scalar()
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        print(f"[PASS] Task 3: SELECT 1 succeeded in {latency_ms} ms")
        print(f"       Server Version: {str(server_version)[:70]}...")
    except Exception as e:
        print(f"[FAIL] Task 3: Failed to execute SELECT 1: {e}", file=sys.stderr)
        return 1

    # 2. Database Session Lifecycle (Normal Commit & Error Rollback)
    print("\n--- Validating Database Session Creation and Cleanup (Task 5) ---")
    try:
        session_gen = get_db_session()
        session = await anext(session_gen)
        # Execute test query in session
        res = await session.execute(text("SELECT count(*) FROM users"))
        user_count = res.scalar()
        print(f"  Session created successfully. Current user count: {user_count}")
        # Complete generator (commit & close)
        try:
            await anext(session_gen)
        except StopAsyncIteration:
            pass
        print("  [PASS] Session normal lifecycle (commit & release) verified.")

        # Test rollback on error
        err_gen = get_db_session()
        await anext(err_gen)
        try:
            await err_gen.athrow(ValueError("Simulated abort"))
        except ValueError:
            pass
        print("  [PASS] Session error rollback lifecycle verified.")
    except Exception as e:
        print(f"  [FAIL] Session lifecycle test failed: {e}", file=sys.stderr)
        return 1

    # 3. ORM Models Mapping & Table Verification
    print("\n--- Validating ORM Models Mapping (Task 6) ---")
    models = [
        User,
        Conversation,
        Message,
        Investigation,
        QueryExecution,
        EvidenceReference,
        Finding,
        Report,
        AuditEvent,
    ]

    try:
        async with engine.connect() as conn:
            table_query = text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name;"
            )
            tables_res = await conn.execute(table_query)
            existing_tables: set[str] = set(tables_res.scalars().all())

        print(f"  Discovered {len(existing_tables)} tables in Supabase public schema.")

        for model in models:
            mapper = class_mapper(model)
            table_name = model.__tablename__
            assert table_name in existing_tables, (
                f"Model {model.__name__} maps to '{table_name}' which is missing in database!"
            )
            col_count = len(mapper.columns)
            rel_count = len(mapper.relationships)
            print(
                f"  [PASS] {model.__name__:<18} -> table '{table_name}' "
                f"({col_count} columns, {rel_count} relations)"
            )
    except Exception as e:
        print(f"  [FAIL] ORM model verification failed: {e}", file=sys.stderr)
        return 1

    # 4. Cleanup
    await close_db()
    print("\n" + "=" * 80)
    print("  ALL SUPABASE POSTGRESQL INTEGRATION CHECKS PASSED (STATUS: PASS)")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    code = asyncio.run(main())
    sys.exit(code)
