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

    from backend.app.agents.graph import investigation_workflow
    from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext

    # 4. Record analyst's user message
    user_msg = Message(
        conversation_id=conv.id,
        role="user",
        content=req.message,
        request_id=request_id,
    )
    session.add(user_msg)
    await session.flush()

    # 5. Execute through LangGraph Multi-Agent Investigation Workflow
    workflow_state: InvestigationState = {
        "request_id": request_id,
        "user_id": current_user.id,
        "conversation_id": conv.id,
        "investigation_id": inv.id,
        "provider_name": provider.name,
        "user_query": req.message,
        "resolved_context": ResolvedInvestigationContext(
            target_accounts=list(context.target_accounts),
            prior_evidence_ids=list(context.prior_evidence_ids),
            prior_time_range=context.prior_time_range,
        ),
    }

    workflow_res = await investigation_workflow.ainvoke(workflow_state)

    val_result = workflow_res.get("validation_result")
    query_spec = workflow_res.get("query_plan")
    events = workflow_res.get("events", [])
    evidence_ids = workflow_res.get("evidence_ids", [])
    workflow_findings = workflow_res.get("findings", [])
    final_response = workflow_res.get("final_response", "")

    if val_result is not None and not val_result.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query validation rejected: {[e.message for e in val_result.errors]}",
        )

    # 6. Record query execution audit
    search_req = QueryCompiler.compile_to_search_request(query_spec) if query_spec else None
    qexec = QueryExecution(
        investigation_id=inv.id,
        provider=provider.name,
        query_spec=query_spec.model_dump(mode="json") if query_spec else {},
        compiled_query_redacted=search_req.model_dump(mode="json") if search_req else {},
        validation_status="valid" if (val_result and val_result.is_valid) else "invalid",
        execution_status="success",
        result_count=len(events),
        duration_ms=workflow_res.get("provider_results_metadata", {}).get("took_ms", 0),
    )
    session.add(qexec)

    # 7. Record evidence references
    for ev in events:
        eref = EvidenceReference(
            investigation_id=inv.id,
            provider=provider.name,
            index_name="synthetic-events" if provider.name == "synthetic" else "live-events",
            document_id=ev.event.id,
            event_id=ev.event.id,
            event_timestamp=ev.timestamp,
            snapshot={
                "action": ev.event.action,
                "outcome": ev.event.outcome.value if ev.event.outcome else None,
            },
        )
        session.add(eref)

    # 8. Convert workflow findings to FindingItem and record in DB
    findings: list[FindingItem] = []
    suspect_accounts: set[str] = set(context.target_accounts)

    for ev in events:
        if ev.user and ev.user.name:
            suspect_accounts.add(ev.user.name)

    for wf in workflow_findings:
        f_item = FindingItem(
            finding_type=wf.finding_type,
            title=wf.title,
            description=wf.description,
            classification=wf.classification,
            severity=wf.severity,
            confidence_label=wf.confidence_label,
            evidence_ids=wf.evidence_ids,
        )
        findings.append(f_item)

        db_finding = Finding(
            investigation_id=inv.id,
            finding_type=wf.finding_type,
            title=wf.title,
            description=wf.description,
            classification=wf.classification,
            severity=wf.severity,
            confidence_label=wf.confidence_label,
            evidence_ids=wf.evidence_ids,
        )
        session.add(db_finding)

    # 9. Follow-up suggestions
    if "success" in str(query_spec.filters if query_spec else []):
        suggestions = [
            "Investigate host activity for these accounts",
            "Look for evidence of lateral movement",
            "Generate a report for this investigation",
        ]
    else:
        suggestions = [
            "Did any of those accounts log in successfully afterwards?",
            "Show the top source IP addresses associated with those failures.",
            "Generate a report for this investigation.",
        ]

    # 10. Record assistant response in messages
    meta = {
        "suspect_accounts": sorted(suspect_accounts),
        "evidence_ids": evidence_ids,
        "query_spec": query_spec.model_dump(mode="json") if query_spec else None,
        "result_count": len(events),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    asst_msg = Message(
        conversation_id=conv.id,
        role="assistant",
        content=final_response,
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
        assistant_message=final_response,
        query_spec=query_spec,
        validation_status="valid",
        result_count=len(events),
        evidence_ids=evidence_ids,
        findings=findings,
        data_mode=settings.sentinel_data_mode.value,
        follow_up_suggestions=suggestions,
    )
