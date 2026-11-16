# CHANGELOG — SENTINEL AI (SIH25173)

All notable changes and milestones for the SENTINEL AI platform are documented in this file.

## [0.1.0] - 2026-11-16

### Phase 0: Repository Discovery & Foundation
- Initialized Git repository and configured `.gitignore`, `.editorconfig`, `.env.example`, and `pyproject.toml`.
- Detected Python 3.12.10, Node v25.8.1, uv 0.11.14.
- Implemented typed `Settings` using Pydantic v2 `BaseSettings`.
- Implemented JWT token encoding/decoding and bcrypt password hashing.
- Implemented FastAPI factory, lifespan handlers, and `/api/v1/health/live`, `/api/v1/health/ready` endpoints.

### Phase 1: Synthetic Vertical Slice & Core System
- **Canonical Event Schema:** Designed and implemented strict ECS-compatible `SecurityEvent` model (`extra="forbid"`) with source provenance and metadata.
- **Deterministic Synthetic Provider:** Implemented `SyntheticEventGenerator` covering 10 scenarios (94 events) and `SyntheticProvider` implementing `ProviderInterface` with filtering, sorting, cursor pagination, and aggregations.
- **Sentinel Query Specification (SQS):** Implemented strict `TimeRange`, `QueryFilter`, `QueryAggregation`, and `SentinelQuerySpec` models.
- **Field Registry & Query Safety Validator:** Authoritative ECS field catalog, operator type checking, time-window bounds, page size limits, and non-aggregatable field rejection.
- **Persistence & Alembic Migrations:** Configured SQLAlchemy 2.x async engine, async session dependency, and all 9 entities (`users`, `conversations`, `messages`, `investigations`, `query_executions`, `evidence_references`, `findings`, `reports`, `audit_events`). Generated and verified Alembic migration `7dc240726238`.
- **Query Preview & Execute API:** `/api/v1/queries/preview` and `/api/v1/queries/execute` with mandatory query validation before execution.
- **Conversational Investigation & Multi-Turn Resolver:** Implemented `IntentPlanner` with multi-turn entity resolution ("Did any of those accounts log in successfully afterwards?").
- **Automated Reporting:** Implemented `ReportService` producing ReportLab PDF reports (with mandatory `SYNTHETIC DATA` watermark banner), JSON export, and defensive CSV export against formula injection.
- **Frontend Workspace:** Built responsive React + TypeScript + Vite + Tailwind CSS dashboard with persistent synthetic mode banner, conversational workspace, query inspector, evidence panel, reports exporter, and settings view.
- **Quality Assurance:** 75/75 automated unit and integration tests passing; 0 Ruff errors; 0 Mypy typing errors.

### Phase 2: Live SIEM Adapters & Dynamic Provider Registry
- **Elasticsearch 8.x Adapter:** Read-only Elasticsearch 8.x client with deterministic Query DSL compiler (`ElasticsearchDslCompiler`), index pattern allowlist enforcement (`Settings.elasticsearch_index_allowlist`), shard failure honesty reporting (`is_partial=True`), and live mapping discovery.
- **Wazuh Manager API Adapter:** Wazuh REST API integration with automated JWT authentication, token caching and expiry refresh, alert retrieval, alert level to canonical severity mapping (levels 1-16 to 0-100), and canonical event normalization.
- **Provider Registry:** Centralized `ProviderRegistry` lifecycle manager supporting dynamic provider resolution (`synthetic`, `elasticsearch`, `wazuh`) and clean connection teardown in FastAPI lifespan.

### Phase 3 & 4: Multi-Agent Orchestration, Threat Intelligence & Risk Engine
- **LangGraph Investigation Workflow:** Implemented stateful `StateGraph` multi-agent workflow exchanging typed contracts (`InvestigationState`, `InvestigationIntent`, `ExtractedEntity`, `ResolvedInvestigationContext`, `InvestigationFinding`, `WorkflowError`).
- **Safety Routing & Execution Halts:** Conditional router enforces immediate halt before query execution when query validation fails, routing to a structured clarification node.
- **MITRE ATT&CK Catalog & Mapper:** Versioned local snapshot of approved Enterprise techniques (`MITRE_CATALOG`) and deterministic mapper (`MitreMapper`) mapping brute force (`T1110.001`), valid accounts (`T1078`), PowerShell execution (`T1059.001`), SSH lateral movement (`T1021.004`), ransomware (`T1486`), and port scanning (`T1046`).
- **Deterministic Correlation Engine:** Implemented explicit entity and temporal correlation patterns (`CORR_001` to `CORR_004`) linking authentication failure sequences with subsequent successful logons, credential spraying, multi-origin logins, and process execution post-auth.
- **Transparent Risk Scoring Engine:** Deterministic and explainable risk scoring (`RiskEngine`) with score drivers, mitigating deductions, and bounded severity thresholds (`informational`, `low`, `medium`, `high`, `critical`).
- **Conversational API Integration:** Rewired `/api/v1/chat` endpoint to execute the full LangGraph investigation graph with complete DB audit logging and evidence tracking.

### Phase 5 & 6: Deployment, Hardening & Evaluation
- **Evaluation Benchmark:** Structured evaluation dataset (`evaluation/questions.json`) covering all 10 Appendix B scenarios and automated runner (`test_evaluation_runner.py`) verifying 100% benchmark passage.
- **Adversarial Security Hardening:** Verified prompt injection resistance (injection strings in log messages treated strictly as inert data), SQL/script injection rejection in queries, CSV spreadsheet formula sanitization, and PDF synthetic data watermark enforcement.
- **Containerization & Deployment:** Created multi-stage `backend/Dockerfile` with non-root user `sentinel`, multi-stage `frontend/Dockerfile` with optimized Nginx runner and security headers, and `docker-compose.yml` orchestrating PostgreSQL, Elasticsearch, backend, and frontend.
- **Final Verification:** 118/118 tests passing; 0 Ruff lint errors; 0 Mypy type errors across 59 source files; frontend production build verified.
- **Evaluation CLI Runner:** Standalone benchmark script `scripts/run_evaluation.py` measuring per-scenario pipeline latency (12.5ms avg), SQS validity rate (100%), and hit counts.
- **Live End-to-End API Verification:** Executed live multi-turn walkthrough (`scripts/verify_live_api.py`) verifying real Uvicorn daemon, auth flow, LangGraph turn 1 & 2 execution, and ReportLab PDF/CSV artifact downloads.
