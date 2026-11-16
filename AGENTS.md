# SENTINEL AI — Agent Instructions

**Project:** SIH25173 — Conversational SIEM Assistant for Investigation and Automated Threat Reporting using NLP  
**Product name:** SENTINEL AI  
**Master specification:** See `SENTINEL_AI_Master_System_Prompt_AGENTS.md` for the complete autonomous build blueprint.

## Quick Reference

1. Read `SENTINEL_AI_Master_System_Prompt_AGENTS.md` completely before any implementation.
2. Read `PROGRESS.md` to identify current state and next task.
3. Inspect repository, Git status, and existing code before changes.
4. Implement incrementally as verified vertical slices.
5. Run tests after every meaningful change.
6. Record actual results in `PROGRESS.md`.
7. Never fabricate test results, events, or metrics.

## Frozen Stack

- Backend: Python 3.12+ / FastAPI / Pydantic v2 / SQLAlchemy 2.x + Alembic
- Frontend: React + TypeScript + Vite + Tailwind CSS + TanStack Query + Plotly
- SIEM: Elasticsearch / Wazuh / Synthetic provider
- Orchestration: LangGraph
- Database: PostgreSQL (SQLite for compatible tests)
- Reports: ReportLab PDF, JSON, CSV
- Auth: JWT / RBAC
- Deployment: Docker Compose
