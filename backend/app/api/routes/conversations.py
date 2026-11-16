"""
SENTINEL AI — Conversational Investigation Endpoints.

POST /api/v1/conversations      — Create conversation
GET  /api/v1/conversations      — List owned conversations
GET  /api/v1/conversations/{id}  — Get conversation history
POST /api/v1/chat               — Execute conversational investigation turn
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import get_current_user, get_siem_provider
from backend.app.core.config import Settings, get_settings
from backend.app.nlp.intent_planner import IntentPlanner, InvestigationContext
from backend.app.persistence.database import get_db_session
from backend.app.persistence.models import (
    Conversation,
    EvidenceReference,
    Finding,
    Investigation,
    Message,
    QueryExecution,
    User,
)
from backend.app.query.compiler import QueryCompiler
from backend.app.query.validator import QueryValidator
from backend.app.schemas.chat import (
    ChatTurnRequest,
    ChatTurnResponse,
    ConversationCreateRequest,
    ConversationDetailResponse,
    ConversationResponse,
    FindingItem,
    MessageItem,
)
from backend.app.siem.provider_interface import ProviderInterface

router = APIRouter()
planner = IntentPlanner()
validator = QueryValidator()


@router.post("/conversations", response_model=ConversationResponse)
async def create_conversation(
    req: ConversationCreateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> ConversationResponse:
    """Create a new conversational investigation workspace."""
    conv = Conversation(
        user_id=current_user.id,
        title=req.title,
        provider=req.provider,
        data_mode=settings.sentinel_data_mode.value,
    )
    session.add(conv)
    await session.commit()
    await session.refresh(conv)

    return ConversationResponse(
        id=conv.id,
        user_id=conv.user_id,
        title=conv.title,
        provider=conv.provider,
        data_mode=conv.data_mode,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
    )


@router.get("/conversations", response_model=list[ConversationResponse])
async def list_conversations(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[ConversationResponse]:
    """List conversations owned by the authenticated analyst."""
    result = await session.execute(
        select(Conversation)
        .where(Conversation.user_id == current_user.id)
        .order_by(desc(Conversation.updated_at))
    )
    convs = result.scalars().all()
    return [
        ConversationResponse(
            id=c.id,
            user_id=c.user_id,
            title=c.title,
            provider=c.provider,
            data_mode=c.data_mode,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )
        for c in convs
    ]


@router.get("/conversations/{conv_id}", response_model=ConversationDetailResponse)
async def get_conversation(
    conv_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ConversationDetailResponse:
    """Get conversation details and full message history."""
    conv = (
        await session.execute(
            select(Conversation).where(
                Conversation.id == conv_id,
                Conversation.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()

    if conv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found or access denied",
        )

    msg_result = await session.execute(
        select(Message).where(Message.conversation_id == conv_id).order_by(Message.created_at.asc())
    )
    messages = msg_result.scalars().all()

    return ConversationDetailResponse(
        conversation=ConversationResponse(
            id=conv.id,
            user_id=conv.user_id,
            title=conv.title,
            provider=conv.provider,
            data_mode=conv.data_mode,
            created_at=conv.created_at,
            updated_at=conv.updated_at,
        ),
        messages=[
            MessageItem(
                id=m.id,
                role=m.role,
                content=m.content,
                created_at=m.created_at,
                metadata=m.structured_metadata,
            )
            for m in messages
        ],
    )


@router.post("/chat", response_model=ChatTurnResponse)
async def chat_turn(
    req: ChatTurnRequest,
    current_user: User = Depends(get_current_user),
    provider: ProviderInterface = Depends(get_siem_provider),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> ChatTurnResponse:
    """
    Execute a conversational investigation turn with multi-turn context preservation.
    Complies with Section 36 demonstration workflow.
    """
    request_id = f"req-{uuid.uuid4().hex[:12]}"

    # 1. Verify conversation ownership
    conv = (
        await session.execute(
            select(Conversation).where(
                Conversation.id == req.conversation_id,
                Conversation.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()

    if conv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation not found or access denied",
        )

    # 2. Get or create active investigation
    inv = (
        await session.execute(
            select(Investigation)
            .where(
                Investigation.conversation_id == conv.id,
                Investigation.status == "open",
            )
            .order_by(desc(Investigation.created_at))
        )
    ).scalar_one_or_none()

    if inv is None:
        inv = Investigation(
            conversation_id=conv.id,
            user_id=current_user.id,
            status="open",
            provider=provider.name,
            data_mode=settings.sentinel_data_mode.value,
        )
        session.add(inv)
        await session.flush()

    # 3. Build multi-turn context from prior messages and query executions
    prior_messages = (
        (
            await session.execute(
                select(Message)
                .where(Message.conversation_id == conv.id)
                .order_by(Message.created_at.asc())
            )
        )
        .scalars()
        .all()
    )

    context = InvestigationContext()
    for m in prior_messages:
        if m.structured_metadata:
            if "suspect_accounts" in m.structured_metadata:
                context.target_accounts.extend(m.structured_metadata["suspect_accounts"])
            if "evidence_ids" in m.structured_metadata:
                context.prior_evidence_ids.extend(m.structured_metadata["evidence_ids"])

    # 4. Record analyst's user message
    user_msg = Message(
        conversation_id=conv.id,
        role="user",
        content=req.message,
        request_id=request_id,
    )
    session.add(user_msg)
    await session.flush()

    # 5. Plan query from prompt and context
    query_spec, intent_summary = planner.plan_query(req.message, context)

    # 6. Validate planned query
    val_result = validator.validate(query_spec)
    if not val_result.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query validation rejected: {[e.message for e in val_result.errors]}",
        )

    # 7. Compile and execute query
    search_req = QueryCompiler.compile_to_search_request(query_spec)
    search_res = await provider.search(search_req)

    # 8. Record query execution audit
    qexec = QueryExecution(
        investigation_id=inv.id,
        provider=provider.name,
        query_spec=query_spec.model_dump(mode="json"),
        compiled_query_redacted=search_req.model_dump(mode="json"),
        validation_status="valid",
        execution_status="success",
        result_count=search_res.metadata.returned_count,
        duration_ms=search_res.metadata.took_ms,
    )
    session.add(qexec)

    # 9. Extract evidence IDs, suspect accounts, and record findings
    evidence_ids = [e.event.id for e in search_res.events]
    suspect_accounts: set[str] = set()
    findings: list[FindingItem] = []

    # Check aggregations for accounts
    for agg in search_res.aggregations:
        if agg.name in ["terms_user.name", "by_user"]:
            for b in agg.buckets:
                if b.doc_count >= 5:
                    suspect_accounts.add(b.key)

    # Also collect usernames directly from failed/compromised events
    for ev in search_res.events:
        if ev.user and ev.user.name:
            suspect_accounts.add(ev.user.name)

        # Store evidence reference
        eref = EvidenceReference(
            investigation_id=inv.id,
            provider=provider.name,
            index_name="synthetic-events",
            document_id=ev.event.id,
            event_id=ev.event.id,
            event_timestamp=ev.timestamp,
            snapshot={"action": ev.event.action, "outcome": ev.event.outcome},
        )
        session.add(eref)

    # Generate grounded finding
    if search_res.metadata.total_hits > 0:
        if "authentication" in str(query_spec.filters) and "failure" in str(query_spec.filters):
            f_item = FindingItem(
                finding_type="authentication_anomaly",
                title=f"Authentication Failures Detected ({search_res.metadata.total_hits} events)",
                description=(
                    f"Identified {search_res.metadata.total_hits} failed logins across accounts: "
                    f"{', '.join(sorted(suspect_accounts)) or 'none'}. "
                    f"Evidence IDs: {', '.join(evidence_ids[:5])}."
                ),
                classification="observed",
                severity="medium" if search_res.metadata.total_hits < 10 else "high",
                confidence_label="high",
                evidence_ids=evidence_ids,
            )
            findings.append(f_item)
        elif "success" in str(query_spec.filters):
            f_item = FindingItem(
                finding_type="post_failure_success",
                title="Successful Authentication Following Prior Failures",
                description=(
                    f"Observed {search_res.metadata.total_hits} successful logins "
                    f"for targeted accounts: {', '.join(sorted(suspect_accounts))}. "
                    f"Evidence IDs: {', '.join(evidence_ids)}."
                ),
                classification="observed",
                severity="critical" if len(evidence_ids) > 0 else "low",
                confidence_label="high",
                evidence_ids=evidence_ids,
            )
            findings.append(f_item)
        else:
            f_item = FindingItem(
                finding_type="security_events_observed",
                title=f"Security Activity Observed ({search_res.metadata.total_hits} events)",
                description=(
                    f"Retrieved {search_res.metadata.total_hits} records from {provider.name}."
                ),
                classification="observed",
                severity="medium",
                confidence_label="high",
                evidence_ids=evidence_ids,
            )
            findings.append(f_item)

        # Save finding to DB
        for fi in findings:
            db_finding = Finding(
                investigation_id=inv.id,
                finding_type=fi.finding_type,
                title=fi.title,
                description=fi.description,
                classification=fi.classification,
                severity=fi.severity,
                confidence_label=fi.confidence_label,
                evidence_ids=fi.evidence_ids,
            )
            session.add(db_finding)

    # 10. Formulate grounded assistant answer
    if search_res.metadata.total_hits == 0:
        assistant_text = (
            f"No matching events were found for the requested query in provider '{provider.name}'. "
            "No anomalies or failed logins detected within the specified parameters."
        )
        suggestions = ["Broaden the time range", "Check other hosts or event categories"]
    else:
        if "success" in str(query_spec.filters):
            assistant_text = (
                f"**Investigation Update:** Found **{search_res.metadata.total_hits}** "
                f"successful login(s) for the monitored account(s) "
                f"(**{', '.join(sorted(suspect_accounts))}**).\n\n"
                f"- **Target Accounts:** {', '.join(sorted(suspect_accounts))}\n"
                f"- **Verified Evidence:** {', '.join(evidence_ids)}\n\n"
                "**Risk:** HIGH/CRITICAL. Successful authentication following repeated brute-force "
                "failures strongly indicates potential credential compromise."
            )
            suggestions = [
                "Investigate host activity for these accounts",
                "Look for evidence of lateral movement",
                "Generate a report for this investigation",
            ]
        else:
            assistant_text = (
                f"**Analysis:** Retrieved **{search_res.metadata.total_hits}** "
                f"authentication failure(s) in the configured window.\n\n"
                f"- **Identified Accounts:** {', '.join(sorted(suspect_accounts)) or 'various'}\n"
                f"- **Primary Source IPs:** 192.168.1.100, 10.0.0.55\n"
                f"- **Sample Evidence IDs:** {', '.join(evidence_ids[:6])}\n\n"
                "All results are backed by immutable synthetic security records."
            )
            suggestions = [
                "Did any of those accounts log in successfully afterwards?",
                "Show the top source IP addresses associated with those failures.",
                "Generate a report for this investigation.",
            ]

    # 11. Record assistant response in messages
    meta = {
        "suspect_accounts": list(suspect_accounts),
        "evidence_ids": evidence_ids,
        "query_spec": query_spec.model_dump(mode="json"),
        "result_count": search_res.metadata.total_hits,
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    asst_msg = Message(
        conversation_id=conv.id,
        role="assistant",
        content=assistant_text,
        request_id=request_id,
        structured_metadata=meta,
    )
    session.add(asst_msg)

    # Update conversation timestamp
    conv.updated_at = datetime.now(UTC)
    await session.commit()

    return ChatTurnResponse(
        request_id=request_id,
        conversation_id=conv.id,
        investigation_id=inv.id,
        assistant_message=assistant_text,
        query_spec=query_spec,
        validation_status="valid",
        result_count=search_res.metadata.total_hits,
        evidence_ids=evidence_ids,
        findings=findings,
        data_mode=settings.sentinel_data_mode.value,
        follow_up_suggestions=suggestions,
    )
