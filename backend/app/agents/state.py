"""
SENTINEL AI — LangGraph Typed State & Agent Contracts.

All workflow nodes exchange Pydantic-validated models per Section 6.1 & 6.2.
No free-form model-generated executable commands are passed between nodes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict

from backend.app.domain.events import SecurityEvent
from backend.app.investigation.correlation import Correlation
from backend.app.investigation.mitre import AttackTechniqueCandidate
from backend.app.investigation.risk import RiskAssessment
from backend.app.query.sqs import SentinelQuerySpec, TimeRange
from backend.app.query.validator import QueryValidationResult
from pydantic import BaseModel, ConfigDict, Field


class InvestigationIntent(BaseModel):
    """Structured analyst inquiry intent."""

    model_config = ConfigDict(extra="forbid")

    intent_type: str  # search, summarize, correlate, report, clarify
    description: str
    confidence: float = 1.0


class ExtractedEntity(BaseModel):
    """Entity extracted from query or context."""

    model_config = ConfigDict(extra="forbid")

    entity_type: str  # ip, user, host, process, file, rule
    value: str
    role: str = "subject"  # source, target, subject


class ResolvedInvestigationContext(BaseModel):
    """Multi-turn context preserved across messages."""

    model_config = ConfigDict(extra="forbid")

    prior_time_range: TimeRange | None = None
    target_accounts: list[str] = Field(default_factory=list)
    target_ips: list[str] = Field(default_factory=list)
    target_hosts: list[str] = Field(default_factory=list)
    prior_evidence_ids: list[str] = Field(default_factory=list)
    prior_query_id: str | None = None


class SchemaContext(BaseModel):
    """Schema context for query translation."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    allowed_fields: list[str] = Field(default_factory=list)
    field_mappings: dict[str, str] = Field(default_factory=dict)


class CompiledProviderQuery(BaseModel):
    """Provider-specific compiled query details."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    compiled_body: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class EvidenceReferenceModel(BaseModel):
    """Reference linking an investigation finding directly to a stored event."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    event_id: str
    provider: str
    timestamp: datetime
    event_category: str
    summary: str
    data_mode: str = "synthetic"


class InvestigationFinding(BaseModel):
    """Specific security observation supported by verified evidence."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding_type: str = "observed_activity"
    title: str
    description: str
    classification: str = "observed"
    severity: str  # low, medium, high, critical, informational
    confidence_label: str = "high"
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ReportRequestModel(BaseModel):
    """Request to export investigation findings."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    format: str  # pdf, json, csv
    title: str
    include_evidence: bool = True


class ReportArtifactModel(BaseModel):
    """Generated report artifact reference."""

    model_config = ConfigDict(extra="forbid")

    report_id: str
    file_path: str
    format: str
    size_bytes: int
    download_url: str


class WorkflowError(BaseModel):
    """Typed workflow error representation."""

    model_config = ConfigDict(extra="forbid")

    error_code: str
    message: str
    is_transient: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationState(TypedDict, total=False):
    """
    LangGraph TypedState matching Section 6.2.
    """

    request_id: str
    user_id: str
    conversation_id: str
    investigation_id: str
    provider_name: str
    user_query: str
    intent: InvestigationIntent | None
    entities: list[ExtractedEntity]
    resolved_context: ResolvedInvestigationContext | None
    schema_context: SchemaContext | None
    query_plan: SentinelQuerySpec | None
    validation_result: QueryValidationResult | None
    compiled_query_metadata: dict[str, Any]
    provider_results_metadata: dict[str, Any]
    events: list[SecurityEvent]
    evidence_ids: list[str]
    findings: list[InvestigationFinding]
    correlations: list[Correlation]
    attack_candidates: list[AttackTechniqueCandidate]
    risk_assessment: RiskAssessment | None
    report_request: ReportRequestModel | None
    report_artifact: ReportArtifactModel | None
    warnings: list[str]
    errors: list[str]
    final_response: str
