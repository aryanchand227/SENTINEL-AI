"""
SENTINEL AI — Report Schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["pdf", "json", "csv"] = "pdf"
    title: str = "Investigation Threat Report"


class ReportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    investigation_id: str
    user_id: str
    format: str
    status: str
    data_mode: str
    artifact_path: str
    sha256: str
    download_url: str
    created_at: datetime
