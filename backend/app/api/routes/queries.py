"""
SENTINEL AI — Query preview and execution endpoints.

POST /api/v1/queries/preview  — Validate SQS and return compiled provider query preview
POST /api/v1/queries/execute  — Validate, compile, and execute search on read-only SIEM provider
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import get_current_user, get_siem_provider
from backend.app.core.config import Settings, get_settings
from backend.app.persistence.database import get_db_session
from backend.app.persistence.models import QueryExecution, User
from backend.app.query.compiler import QueryCompiler
from backend.app.query.validator import QueryValidator
from backend.app.schemas.queries import (
    QueryExecuteRequest,
    QueryExecuteResponse,
    QueryPreviewRequest,
    QueryPreviewResponse,
)
from backend.app.siem.provider_interface import ProviderInterface

router = APIRouter()
validator = QueryValidator()


@router.post("/preview", response_model=QueryPreviewResponse)
async def preview_query(
    req: QueryPreviewRequest,
    current_user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> QueryPreviewResponse:
    """Validate SQS and return compiled provider query preview without execution."""
    val_result = validator.validate(req.spec)
    compiled: dict[str, Any] | None = None

    if val_result.is_valid:
        search_req = QueryCompiler.compile_to_search_request(req.spec)
        compiled = search_req.model_dump()

    return QueryPreviewResponse(
        is_valid=val_result.is_valid,
        errors=val_result.errors,
        warnings=val_result.warnings,
        compiled_request=compiled,
        provider=settings.siem_provider.value,
        data_mode=settings.sentinel_data_mode.value,
    )


@router.post("/execute", response_model=QueryExecuteResponse)
async def execute_query(
    req: QueryExecuteRequest,
    current_user: User = Depends(get_current_user),
    provider: ProviderInterface = Depends(get_siem_provider),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> QueryExecuteResponse:
    """Validate, compile, and execute an approved search against the configured provider."""
    # 1. Enforce validation before execution (Security boundary: Section 6.3/8.2)
    val_result = validator.validate(req.spec)
    if not val_result.is_valid:
        error_msgs = "; ".join(f"{e.field}: {e.message}" for e in val_result.errors)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Query validation failed: {error_msgs}",
        )

    # 2. Compile to Provider SearchRequest
    search_req = QueryCompiler.compile_to_search_request(req.spec)

    # 3. Execute search via provider interface
    search_result = await provider.search(search_req)

    # 4. Record execution in query_executions audit log
    execution_id = str(uuid.uuid4())
    record = QueryExecution(
        id=execution_id,
        investigation_id=req.investigation_id,
        provider=provider.name,
        query_spec=req.spec.model_dump(mode="json"),
        compiled_query_redacted=search_req.model_dump(mode="json"),
        validation_status="valid",
        execution_status="success",
        result_count=search_result.metadata.returned_count,
        duration_ms=search_result.metadata.took_ms,
    )
    session.add(record)
    await session.commit()

    # 5. Serialize events into JSON-compatible response
    serialized_events = [
        event.model_dump(mode="json", by_alias=True) for event in search_result.events
    ]

    return QueryExecuteResponse(
        execution_id=execution_id,
        provider=provider.name,
        data_mode=settings.sentinel_data_mode.value,
        metadata=search_result.metadata,
        events=serialized_events,
        aggregations=search_result.aggregations,
    )
