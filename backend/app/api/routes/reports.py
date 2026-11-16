"""
SENTINEL AI — Report Generation and Download Endpoints.

POST /api/v1/investigations/{id}/reports  — Generate immutable report artifact (PDF, JSON, CSV)
GET  /api/v1/reports/{id}                 — Retrieve report metadata
GET  /api/v1/reports/{id}/download        — Download verified report artifact
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import get_current_user
from backend.app.core.config import Settings, get_settings
from backend.app.persistence.database import get_db_session
from backend.app.persistence.models import (
    EvidenceReference,
    Finding,
    Investigation,
    Report,
    User,
)
from backend.app.reporting.service import ReportService
from backend.app.schemas.reports import GenerateReportRequest, ReportResponse

router = APIRouter()
report_service = ReportService()


@router.post("/investigations/{investigation_id}/reports", response_model=ReportResponse)
async def generate_report(
    investigation_id: str,
    req: GenerateReportRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> ReportResponse:
    """Generate an immutable report artifact from an authorized investigation snapshot."""
    # 1. Verify investigation exists and belongs to current user
    inv = (
        await session.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()

    if inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found or access denied",
        )

    # 2. Gather findings and evidence snapshot
    findings_rows = (
        (await session.execute(select(Finding).where(Finding.investigation_id == investigation_id)))
        .scalars()
        .all()
    )
    findings_list = [
        {
            "title": f.title,
            "description": f.description,
            "classification": f.classification,
            "severity": f.severity,
            "confidence_label": f.confidence_label,
            "evidence_ids": f.evidence_ids,
        }
        for f in findings_rows
    ]

    evidence_rows = (
        (
            await session.execute(
                select(EvidenceReference).where(
                    EvidenceReference.investigation_id == investigation_id
                )
            )
        )
        .scalars()
        .all()
    )
    evidence_list: list[dict[str, Any]] = []
    for e in evidence_rows:
        snapshot = e.snapshot or {}
        evidence_list.append(
            {
                "event_id": e.event_id,
                "timestamp": e.event_timestamp.isoformat(),
                "provider": e.provider,
                "action": snapshot.get("action", "unknown"),
                "outcome": snapshot.get("outcome", "unknown"),
                "user": snapshot.get("user", ""),
                "source_ip": snapshot.get("source_ip", ""),
                "severity": snapshot.get("severity", 0),
            }
        )

    report_id = f"rep-{uuid.uuid4().hex[:12]}"

    # 3. Generate file artifact based on requested format
    if req.format == "pdf":
        artifact_path, sha256 = report_service.generate_pdf_report(
            report_id=report_id,
            investigation_id=investigation_id,
            title=req.title,
            data_mode=inv.data_mode,
            provider=inv.provider,
            summary=inv.summary or "Summary based on verified security event records.",
            findings=findings_list,
            evidence=evidence_list,
        )
    elif req.format == "json":
        artifact_path, sha256 = report_service.generate_json_report(
            report_id=report_id,
            investigation_id=investigation_id,
            title=req.title,
            data_mode=inv.data_mode,
            provider=inv.provider,
            summary=inv.summary or "Summary based on verified security event records.",
            findings=findings_list,
            evidence=evidence_list,
        )
    else:  # csv
        artifact_path, sha256 = report_service.generate_csv_report(
            report_id=report_id,
            evidence=evidence_list,
        )

    # 4. Save report record to DB
    rep_record = Report(
        id=report_id,
        investigation_id=investigation_id,
        user_id=current_user.id,
        format=req.format,
        status="completed",
        data_mode=inv.data_mode,
        artifact_path=str(artifact_path),
        sha256=sha256,
    )
    session.add(rep_record)
    await session.commit()
    await session.refresh(rep_record)

    download_url = f"{settings.api_v1_prefix}/reports/{report_id}/download"

    return ReportResponse(
        id=rep_record.id,
        investigation_id=rep_record.investigation_id,
        user_id=rep_record.user_id,
        format=rep_record.format,
        status=rep_record.status,
        data_mode=rep_record.data_mode,
        artifact_path=rep_record.artifact_path,
        sha256=rep_record.sha256,
        download_url=download_url,
        created_at=rep_record.created_at,
    )


@router.get("/reports/{report_id}", response_model=ReportResponse)
async def get_report_metadata(
    report_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> ReportResponse:
    """Retrieve metadata and verification checksum for an authorized report."""
    rep = (
        await session.execute(
            select(Report).where(
                Report.id == report_id,
                Report.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()

    if rep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied",
        )

    download_url = f"{settings.api_v1_prefix}/reports/{rep.id}/download"

    return ReportResponse(
        id=rep.id,
        investigation_id=rep.investigation_id,
        user_id=rep.user_id,
        format=rep.format,
        status=rep.status,
        data_mode=rep.data_mode,
        artifact_path=rep.artifact_path,
        sha256=rep.sha256,
        download_url=download_url,
        created_at=rep.created_at,
    )


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    """Download the authorized immutable report file."""
    rep = (
        await session.execute(
            select(Report).where(
                Report.id == report_id,
                Report.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()

    if rep is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied",
        )

    file_path = Path(rep.artifact_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file artifact missing from disk",
        )

    media_types = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
    }
    media_type = media_types.get(rep.format, "application/octet-stream")

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=file_path.name,
    )
