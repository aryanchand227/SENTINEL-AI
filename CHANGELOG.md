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
