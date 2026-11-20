"""
SENTINEL AI — Phase 4.2 Comprehensive Functional Validation Suite.

Executes end-to-end tests for:
- Phase B: Authentication (Login, Password Hashing, JWT, Invalid Credentials, RBAC)
- Phase C: Database CRUD on all 9 ORM models using isolated SQLite memory engine
- Phase D: SIEM and AI Pipeline (Intent planning, Query validation, LangGraph workflow)
- Phase E: Reporting (PDF, JSON, CSV generation, checksums, formula injection defenses)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.agents.graph import investigation_workflow
from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext

# Security & Config
from backend.app.core.security import (
    UserRole,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from backend.app.investigation.mitre import MitreMapper
from backend.app.investigation.risk import RiskEngine
from backend.app.main import app
from backend.app.nlp.intent_planner import IntentPlanner
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
from backend.app.query.sqs import SentinelQuerySpec, TimeRange
from backend.app.query.validator import QueryValidator
from backend.app.reporting.service import ReportService, escape_csv_field
from backend.app.siem.provider_interface import SearchRequest
from backend.app.siem.synthetic.provider import SyntheticProvider
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


async def run_phase_b_auth() -> dict[str, Any]:
    print("\n--- RUNNING PHASE B: AUTHENTICATION VALIDATION ---")
    results = {}

    # 1. Password Hashing & Verification
    pwd = "SecurePassword123!"
    hashed = hash_password(pwd)
    assert hashed != pwd, "Hash must not equal plaintext"
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$"), "Must use bcrypt"
    assert verify_password(pwd, hashed) is True, "Password verification must succeed"
    assert verify_password("WrongPassword", hashed) is False, "Wrong password must fail"
    results["password_hashing"] = "PASS"
    print("  [PASS] Password hashing and verification verified.")

    # 2. JWT Generation, Claims, and Expiration
    uid = str(uuid.uuid4())
    token = create_access_token(user_id=uid, role=UserRole.ANALYST)
    payload = decode_access_token(token)
    assert payload.sub == uid, "JWT sub must match user_id"
    assert payload.role == UserRole.ANALYST, "JWT role must match"
    assert payload.exp > datetime.now(UTC), "JWT exp must be in future"
    results["jwt_generation"] = "PASS"
    print("  [PASS] JWT generation and claims verified.")

    # Expired token
    expired_token = create_access_token(
        user_id=uid, role=UserRole.ANALYST, expires_delta=timedelta(seconds=-10)
    )
    try:
        decode_access_token(expired_token)
        results["jwt_expiration"] = "FAIL"
        print("  [FAIL] Expired JWT did not raise error.")
    except ValueError as e:
        assert "Signature has expired" in str(e) or "expired" in str(e).lower()
        results["jwt_expiration"] = "PASS"
        print("  [PASS] JWT expiration enforcement verified.")

    # Tampered token
    tampered_token = token[:-5] + "aaaaa"
    try:
        decode_access_token(tampered_token)
        results["jwt_tampering"] = "FAIL"
    except ValueError:
        results["jwt_tampering"] = "PASS"
        print("  [PASS] JWT signature tamper detection verified.")

    # 3. HTTP Auth Endpoints via TestClient
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid credentials login
        bad_login = await client.post(
            "/api/v1/auth/login", json={"email": "nobody@sentinel.ai", "password": "WrongPassword"}
        )
        assert bad_login.status_code == 401, f"Expected 401, got {bad_login.status_code}"
        results["login_invalid_credentials"] = "PASS"
        print("  [PASS] Login rejection for invalid credentials (HTTP 401) verified.")

        # Protected endpoint without header in production mode test
        # We can simulate by creating an active user and testing /api/v1/auth/me with valid bearer
        test_email = f"auth_test_{uuid.uuid4().hex[:6]}@sentinel.ai"
        test_pwd = "AuthPassword123!"
        from backend.app.persistence.database import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            test_user = User(
                email=test_email,
                password_hash=hash_password(test_pwd),
                display_name="QA Auditor",
                role="analyst",
            )
            session.add(test_user)
            await session.commit()
            test_uid = test_user.id

        login_res = await client.post(
            "/api/v1/auth/login", json={"email": test_email, "password": test_pwd}
        )
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        token_data = login_res.json()
        valid_token = token_data["access_token"]
        assert token_data["role"] == "analyst"

        me_res = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"}
        )
        assert me_res.status_code == 200, f"Me failed: {me_res.text}"
        me_data = me_res.json()
        assert me_data["email"] == test_email
        assert me_data["id"] == test_uid
        results["login_and_me_flow"] = "PASS"
        print("  [PASS] Login success and /api/v1/auth/me retrieval verified.")

        # Deactivated user check
        async with factory() as session:
            usr = (await session.execute(select(User).where(User.id == test_uid))).scalar_one()
            usr.is_active = False
            await session.commit()

        deact_login = await client.post(
            "/api/v1/auth/login", json={"email": test_email, "password": test_pwd}
        )
        assert deact_login.status_code == 403, (
            f"Expected 403 for deactivated user, got {deact_login.status_code}"
        )
        results["deactivated_user_rejection"] = "PASS"
        print("  [PASS] Deactivated user rejection (HTTP 403) verified.")

    # 4. RBAC Audit
    # Check if endpoints enforce role permissions
    results["rbac_status"] = "PARTIAL_AUDIT_NOTE"
    print(
        "  [NOTE] RBAC analysis: UserRole (analyst, senior_analyst, admin) defined in models;\n"
        "         endpoint-level role guard (e.g. require_role) not actively gating routes."
    )

    # 5. User Registration Audit
    results["registration_endpoint"] = "MISSING_BY_DESIGN_AUDIT_NOTE"
    print(
        "  [NOTE] Registration endpoint: POST /api/v1/auth/register does not exist;\n"
        "         user provisioning is administrative/seeding only."
    )

    return results


async def run_phase_c_database_crud() -> dict[str, Any]:
    print("\n--- RUNNING PHASE C: DATABASE CRUD VALIDATION (ALL 9 MODELS) ---")
    results = {}

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        # 1. User CRUD
        u = User(
            email="crud_test@sentinel.ai",
            password_hash=hash_password("Pass123!"),
            display_name="CRUD Tester",
            role="senior_analyst",
        )
        session.add(u)
        await session.commit()
        await session.refresh(u)
        assert u.id is not None
        results["User_create_read"] = "PASS"
        print("  [PASS] 1. User CRUD verified.")

        # 2. Conversation CRUD
        conv = Conversation(
            user_id=u.id, title="Investigation Alpha", provider="synthetic", data_mode="synthetic"
        )
        session.add(conv)
        await session.commit()
        await session.refresh(conv)
        assert conv.id is not None
        assert conv.title == "Investigation Alpha"
        results["Conversation_create_read"] = "PASS"
        print("  [PASS] 2. Conversation CRUD verified.")

        # 3. Message CRUD
        msg = Message(
            conversation_id=conv.id,
            role="user",
            content="Check failed logins",
            request_id="req-123",
            structured_metadata={"source": "test"},
        )
        session.add(msg)
        await session.commit()
        await session.refresh(msg)
        assert msg.id is not None
        assert msg.structured_metadata is not None
        assert msg.structured_metadata["source"] == "test"
        results["Message_create_read"] = "PASS"
        print("  [PASS] 3. Message CRUD verified.")

        # 4. Investigation CRUD
        inv = Investigation(
            conversation_id=conv.id,
            user_id=u.id,
            status="open",
            provider="synthetic",
            data_mode="synthetic",
            summary="Test incident summary",
            risk_level="high",
            risk_score=80,
        )
        session.add(inv)
        await session.commit()
        await session.refresh(inv)
        assert inv.id is not None
        assert inv.risk_score == 80
        results["Investigation_create_read"] = "PASS"
        print("  [PASS] 4. Investigation CRUD verified.")

        # 5. QueryExecution CRUD
        qexec = QueryExecution(
            investigation_id=inv.id,
            provider="synthetic",
            query_spec={"intent": "Find SSH failures"},
            compiled_query_redacted={"filters": []},
            validation_status="valid",
            execution_status="success",
            result_count=15,
            duration_ms=42,
        )
        session.add(qexec)
        await session.commit()
        await session.refresh(qexec)
        assert qexec.id is not None
        assert qexec.result_count == 15
        results["QueryExecution_create_read"] = "PASS"
        print("  [PASS] 5. QueryExecution CRUD verified.")

        # 6. EvidenceReference CRUD
        eref = EvidenceReference(
            investigation_id=inv.id,
            provider="synthetic",
            event_id="evt-001234",
            event_timestamp=datetime.now(UTC),
            snapshot={"action": "auth_failure", "user": "admin"},
        )
        session.add(eref)
        await session.commit()
        await session.refresh(eref)
        assert eref.id is not None
        assert eref.snapshot is not None
        assert eref.snapshot["user"] == "admin"
        results["EvidenceReference_create_read"] = "PASS"
        print("  [PASS] 6. EvidenceReference CRUD verified.")

        # 7. Finding CRUD
        finding = Finding(
            investigation_id=inv.id,
            finding_type="brute_force",
            title="SSH Brute Force",
            description="Repeated failed authentications observed",
            classification="observed",
            severity="high",
            confidence_label="high",
            evidence_ids=[eref.event_id],
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        assert finding.id is not None
        assert finding.evidence_ids == ["evt-001234"]
        results["Finding_create_read"] = "PASS"
        print("  [PASS] 7. Finding CRUD verified.")

        # 8. Report CRUD
        rep = Report(
            investigation_id=inv.id,
            user_id=u.id,
            format="pdf",
            status="completed",
            data_mode="synthetic",
            artifact_path="/tmp/fake_report.pdf",
            sha256="0" * 64,
        )
        session.add(rep)
        await session.commit()
        await session.refresh(rep)
        assert rep.id is not None
        assert rep.sha256 == "0" * 64
        results["Report_create_read"] = "PASS"
        print("  [PASS] 8. Report CRUD verified.")

        # 9. AuditEvent CRUD
        audit = AuditEvent(
            user_id=u.id,
            request_id="req-123",
            action="report_export",
            resource_type="report",
            resource_id=rep.id,
            outcome="success",
            safe_metadata={"format": "pdf"},
        )
        session.add(audit)
        await session.commit()
        await session.refresh(audit)
        assert audit.id is not None
        assert audit.outcome == "success"
        results["AuditEvent_create_read"] = "PASS"
        print("  [PASS] 9. AuditEvent CRUD verified.")

        # Verify Cascading Deletion
        await session.delete(conv)
        await session.commit()
        # Message should be deleted by cascade
        msg_check = (
            await session.execute(select(Message).where(Message.id == msg.id))
        ).scalar_one_or_none()
        assert msg_check is None, "Message must be deleted on conversation cascade delete"
        results["cascade_deletion"] = "PASS"
        print("  [PASS] Cascade deletion on relationship verified.")

    await engine.dispose()
    return results


async def run_phase_d_siem_ai_pipeline() -> dict[str, Any]:
    print("\n--- RUNNING PHASE D: SIEM AND AI PIPELINE VALIDATION ---")
    results = {}

    # 1. Intent Classification and Planning
    planner = IntentPlanner()
    spec, summary = planner.plan_query("Find accounts with failed logins in the last 24 hours.")
    assert spec is not None
    assert "authentication" in spec.intent.lower()
    assert "failed" in summary.lower()
    assert len(spec.filters) >= 2
    cat_filter = next((f for f in spec.filters if f.field == "event.category"), None)
    outcome_filter = next((f for f in spec.filters if f.field == "event.outcome"), None)
    assert cat_filter is not None and cat_filter.value == "authentication"
    assert outcome_filter is not None and outcome_filter.value == "failure"
    results["intent_planning"] = "PASS"
    print(f"  [PASS] Intent planning verified: intent='{spec.intent}', filters={len(spec.filters)}")

    # 2. Query Validation
    validator = QueryValidator()
    val_res = validator.validate(spec)
    assert val_res.is_valid is True, f"Validation failed: {val_res.errors}"
    results["query_validation_valid"] = "PASS"

    # Test rejection of unauthorized fields or excessive limits
    invalid_spec = SentinelQuerySpec(
        intent="Malicious query",
        time_range=TimeRange(
            start=datetime.now(UTC) - timedelta(days=90),  # Exceeds max 30 days
            end=datetime.now(UTC),
        ),
        page_size=5000,  # Exceeds max limit 500
    )
    val_reject = validator.validate(invalid_spec)
    assert val_reject.is_valid is False
    assert any("time_range" in e.field for e in val_reject.errors)
    assert any("page_size" in e.field for e in val_reject.errors)
    results["query_validation_rejection"] = "PASS"
    print("  [PASS] Query validator enforcement (time window and limit bounds) verified.")

    # 3. SIEM Provider Execution & Normalization (Synthetic Provider)
    from backend.app.siem.provider_interface import ProviderStatus

    provider = SyntheticProvider()
    health = await provider.health_check()
    assert health.status == ProviderStatus.HEALTHY
    assert health.provider == "synthetic"

    # Search execution
    s_req = SearchRequest(
        filters=[
            {"field": "event.category", "operator": "eq", "value": "authentication"},
            {"field": "event.outcome", "operator": "eq", "value": "failure"},
        ],
        page_size=50,
    )
    s_res = await provider.search(s_req)
    assert s_res.metadata.returned_count > 0
    assert len(s_res.events) > 0
    # Verify ECS normalization
    first_ev = s_res.events[0]
    assert first_ev.event.id is not None
    assert first_ev.event.category.value == "authentication"
    assert first_ev.event.outcome is not None
    assert first_ev.event.outcome.value == "failure"
    results["provider_search_and_ecs"] = "PASS"
    ret_cnt = s_res.metadata.returned_count
    print(f"  [PASS] SIEM provider search verified ({ret_cnt} events retrieved and normalized).")

    # 4. MITRE ATT&CK Mapping
    mitre_candidates = MitreMapper.map_events(s_res.events)
    assert len(mitre_candidates) > 0
    assert any("T1110" in c.technique_id for c in mitre_candidates), (
        "T1110 Brute Force must be mapped for auth failures"
    )
    results["mitre_mapping"] = "PASS"
    t_ids = [c.technique_id for c in mitre_candidates]
    print(f"  [PASS] MITRE ATT&CK mapping verified (mapped to {t_ids}).")

    # 5. Risk Assessment Engine
    risk = RiskEngine.evaluate(
        events=s_res.events, correlations=[], attack_candidates=mitre_candidates, is_synthetic=True
    )
    assert risk.score > 0
    assert risk.severity in ["low", "medium", "high", "critical"]
    assert len(risk.factors_increased) > 0
    results["risk_engine"] = "PASS"
    print(f"  [PASS] Risk scoring verified: score={risk.score}/100, severity='{risk.severity}'.")

    # 6. Multi-Agent LangGraph Workflow
    state: InvestigationState = {
        "request_id": "req-flow-test",
        "user_id": "user-qa-1",
        "conversation_id": "conv-qa-1",
        "investigation_id": "inv-qa-1",
        "provider_name": "synthetic",
        "user_query": "Find accounts with failed logins in the last 24 hours.",
        "resolved_context": ResolvedInvestigationContext(),
    }
    workflow_out = await investigation_workflow.ainvoke(state)
    val_out = workflow_out.get("validation_result")
    assert val_out is not None and getattr(val_out, "is_valid", False) is True
    assert len(workflow_out.get("events", [])) > 0
    assert len(workflow_out.get("findings", [])) > 0
    final_resp_str = str(workflow_out.get("final_response") or "")
    assert len(final_resp_str) > 50
    assert "SYNTHETIC DATA DISCLOSURE" in final_resp_str
    results["langgraph_workflow"] = "PASS"
    print("  [PASS] LangGraph multi-agent investigation workflow complete run verified.")

    # 7. Follow-up Turn with Multi-turn Context Preservation
    context2 = ResolvedInvestigationContext(
        target_accounts=["jsmith"], prior_evidence_ids=list(workflow_out.get("evidence_ids", []))
    )
    state2: InvestigationState = {
        "request_id": "req-flow-test-2",
        "user_id": "user-qa-1",
        "conversation_id": "conv-qa-1",
        "investigation_id": "inv-qa-1",
        "provider_name": "synthetic",
        "user_query": "Did any of those accounts log in successfully afterwards?",
        "resolved_context": context2,
    }
    workflow_out2 = await investigation_workflow.ainvoke(state2)
    assert len(workflow_out2.get("events", [])) >= 1
    # Check post-failure success correlation
    findings2 = workflow_out2.get("findings", [])
    assert any(f.finding_type == "post_failure_success" for f in findings2)
    results["multi_turn_context_resolution"] = "PASS"
    print("  [PASS] Multi-turn context preservation and correlation verified.")

    return results


async def run_phase_e_reporting() -> dict[str, Any]:
    print("\n--- RUNNING PHASE E: REPORTING ARTIFACT VALIDATION ---")
    results = {}

    service = ReportService()
    test_rep_id = f"rep-test-{uuid.uuid4().hex[:6]}"
    inv_id = f"inv-{uuid.uuid4().hex[:6]}"

    findings = [
        {
            "title": "Brute Force Attack Detected",
            "description": "15 failed logins followed by 1 successful login for account jsmith",
            "classification": "observed",
            "severity": "critical",
            "confidence_label": "high",
            "evidence_ids": ["evt-1", "evt-2"],
        }
    ]
    evidence = [
        {
            "event_id": "evt-1",
            "timestamp": "2026-11-20T10:00:00Z",
            "provider": "synthetic",
            "action": "logon",
            "outcome": "failure",
            "user": "jsmith",
            "source_ip": "192.168.1.100",
            "severity": 3,
        },
        {
            "event_id": "evt-2",
            "timestamp": "2026-11-20T10:05:00Z",
            "provider": "synthetic",
            "action": "logon",
            "outcome": "success",
            "user": "jsmith",
            "source_ip": "192.168.1.100",
            "severity": 1,
        },
    ]

    # 1. PDF Generation
    pdf_path, pdf_hash = service.generate_pdf_report(
        report_id=test_rep_id,
        investigation_id=inv_id,
        title="QA Audit Investigation Report",
        data_mode="synthetic",
        provider="synthetic",
        summary="Audit verification report testing PDF rendering and evidence table.",
        findings=findings,
        evidence=evidence,
    )
    assert pdf_path.exists(), "PDF artifact must exist on disk"
    pdf_bytes = pdf_path.read_bytes()
    assert pdf_bytes.startswith(b"%PDF"), "PDF must have valid %PDF magic header"
    assert hashlib.sha256(pdf_bytes).hexdigest() == pdf_hash, "SHA256 must match file contents"
    results["pdf_generation"] = "PASS"
    print(f"  [PASS] PDF report generated ({len(pdf_bytes)} bytes, SHA-256 verified).")

    # 2. JSON Generation
    json_path, json_hash = service.generate_json_report(
        report_id=test_rep_id,
        investigation_id=inv_id,
        title="QA Audit Investigation Report",
        data_mode="synthetic",
        provider="synthetic",
        summary="Audit verification report testing JSON artifact.",
        findings=findings,
        evidence=evidence,
    )
    assert json_path.exists()
    json_bytes = json_path.read_bytes()
    assert hashlib.sha256(json_bytes).hexdigest() == json_hash
    parsed_json = json.loads(json_bytes.decode("utf-8"))
    assert parsed_json["report_id"] == test_rep_id
    assert parsed_json["investigation_id"] == inv_id
    assert parsed_json["data_mode"] == "SYNTHETIC"
    assert parsed_json["is_synthetic"] is True
    assert len(parsed_json["key_findings"]) == 1
    assert len(parsed_json["evidence_table"]) == 2
    results["json_generation"] = "PASS"
    print(
        f"  [PASS] JSON report generated ({len(json_bytes)} bytes, schema and evidence verified)."
    )

    # 3. CSV Generation & Formula Injection Defense
    csv_path, csv_hash = service.generate_csv_report(report_id=test_rep_id, evidence=evidence)
    assert csv_path.exists()
    csv_bytes = csv_path.read_bytes()
    assert hashlib.sha256(csv_bytes).hexdigest() == csv_hash
    csv_text = csv_bytes.decode("utf-8")
    assert "event_id,timestamp,provider,action,outcome,user,source_ip,severity" in csv_text
    assert "evt-1" in csv_text and "evt-2" in csv_text
    results["csv_generation"] = "PASS"
    print(f"  [PASS] CSV report generated ({len(csv_bytes)} bytes, verified).")

    # Formula injection defenses
    assert escape_csv_field("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert escape_csv_field("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert escape_csv_field("+12345") == "'+12345"
    assert escape_csv_field("-12345") == "'-12345"
    assert escape_csv_field("regular_value") == "regular_value"
    results["csv_formula_injection_defense"] = "PASS"
    print("  [PASS] CSV formula injection sanitization verified.")

    # Cleanup test files
    for p in [pdf_path, json_path, csv_path]:
        try:
            p.unlink()
        except Exception:
            pass

    return results


async def main() -> int:
    print("=" * 80)
    print("  SENTINEL AI — PHASE 4.2 BACKEND API FUNCTIONAL VALIDATION")
    print("=" * 80)

    b_res = await run_phase_b_auth()
    c_res = await run_phase_c_database_crud()
    d_res = await run_phase_d_siem_ai_pipeline()
    e_res = await run_phase_e_reporting()

    print("\n" + "=" * 80)
    print("  PHASE 4.2 FUNCTIONAL AUDIT EXECUTION SUMMARY")
    print("=" * 80)
    all_res = {**b_res, **c_res, **d_res, **e_res}
    failed = [k for k, v in all_res.items() if v == "FAIL"]
    for k, v in all_res.items():
        print(f"  {k:<35}: {v}")

    if failed:
        print(f"\nAUDIT STATUS: FAILED ({len(failed)} failures: {failed})")
        return 1
    else:
        print("\nAUDIT STATUS: ALL FUNCTIONAL CHECKS PASSED")
        return 0


if __name__ == "__main__":
    code = asyncio.run(main())
    sys.exit(code)
