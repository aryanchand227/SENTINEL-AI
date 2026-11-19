# SENTINEL AI (SIH25173) — Pre-Deployment Audit Report

**Date:** 2026-11-19  
**Auditor:** Senior DevOps Engineer & Python/React Architect  
**Project:** SENTINEL AI — Conversational SIEM Assistant (SIH25173)  
**Repository:** [https://github.com/aryanchand227/SENTINEL-AI](https://github.com/aryanchand227/SENTINEL-AI)  
**Target Deployment Topology:**
- **Frontend:** Vercel (React 19 + TypeScript + Vite + Tailwind CSS)
- **Backend:** Render (FastAPI + LangGraph + Uvicorn)
- **Database:** Supabase (Managed PostgreSQL 16)
- **SIEM:** Synthetic (Initial demo) → Wazuh API → Elasticsearch 8.x
- **LLM Runtime:** OpenAI-compatible Cloud Provider (with deterministic offline fallback)

---

## 1. Executive Summary

SENTINEL AI is architecturally sound, thoroughly tested, and ready for deployment following targeted pre-deployment preparations. The application contains zero hardcoded secrets, enforces strict type safety, implements mandatory query validation before SIEM execution, and includes a comprehensive multi-agent LangGraph workflow.

### Verification Status
- **Backend Tests:** **118 passed** across unit and integration suites (`pytest backend/tests/ -v`).
- **Static Analysis & Linting:** **0 errors, 0 warnings** (`ruff check backend/ scripts/`).
- **Type Checking:** **0 errors in 61 files** (`mypy backend/app scripts/`).
- **Frontend Production Build:** **Clean** in 1.99s (`tsc -b && vite build`).
- **Evaluation Benchmark:** **10/10 scenarios passed (100%)** with 12.5 ms average pipeline latency (`scripts/run_evaluation.py`).
- **Live E2E Verification:** Multi-turn investigation and PDF/CSV report generation verified against live daemon (`scripts/verify_live_api.py`).

---

## 2. Repository Structure & Boundary Inspection

```text
SENTINEL-AI/
├── .env.example             # Safe template with placeholder values
├── .gitignore               # Correctly excludes .env, *.db, artifacts/*.pdf, etc.
├── pyproject.toml           # Project metadata, tools, and dependencies
├── docker-compose.yml       # Local multi-container development environment
├── AGENTS.md                # Master engineering contract and rules
├── PROGRESS.md              # Historical verification ledger
├── CHANGELOG.md             # Version history
├── backend/
│   ├── Dockerfile           # Multi-stage Python 3.12-slim non-root container
│   ├── alembic.ini          # Alembic CLI configuration
│   ├── alembic/             # Async migration runner & versions (7dc240726238)
│   ├── app/
│   │   ├── main.py          # FastAPI application factory & entry point (`create_app`)
│   │   ├── lifespan.py      # Startup DB initialization & shutdown provider teardown
│   │   ├── core/            # Settings (Pydantic v2 BaseSettings), security (JWT, bcrypt)
│   │   ├── domain/          # Canonical ECS SecurityEvent schema
│   │   ├── persistence/     # SQLAlchemy 2.x async models & session factory
│   │   ├── query/           # SQS models, ECS FieldRegistry, QueryValidator, QueryCompiler
│   │   ├── agents/          # LangGraph workflow, state contracts & 6 specialized nodes
│   │   ├── investigation/   # MITRE ATT&CK mapper, correlation rules, risk scoring engine
│   │   ├── nlp/             # LLM client abstraction & deterministic intent planner
│   │   ├── siem/            # ProviderInterface, ProviderRegistry, Synthetic, ES 8.x, Wazuh
│   │   ├── reporting/       # ReportLab PDF (watermarked), JSON, defensive CSV service
│   │   ├── schemas/         # API request/response contracts (Pydantic v2)
│   │   └── api/             # FastAPI routes (/health, /auth, /conversations, /queries, /reports)
│   └── tests/               # 118 automated unit and integration tests
├── frontend/
│   ├── package.json         # React 19, TypeScript 7, Vite 8, Tailwind CSS 4, Lucide
│   ├── vite.config.ts       # Vite configuration with local proxy to :8000
│   ├── Dockerfile           # Multi-stage Node builder + Nginx alpine runner
│   ├── nginx.conf           # Hardened production web server configuration
│   └── src/                 # SOC dashboard UI components, hooks, and services
├── evaluation/              # 10 benchmark evaluation questions (Appendix B)
└── scripts/                 # Standalone evaluation & live verification runners
```

---

## 3. Backend & FastAPI Configuration

- **Application Factory:** `backend.app.main:create_app()` returning `FastAPI`.
- **Top-Level ASGI Instance:** `app = create_app()` inside `backend.app.main`.
- **Actual Local Run Command:**
  ```powershell
  uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
  ```
- **Actual Render Run Command:**
  ```bash
  uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT
  ```
- **Health Probes:**
  - `GET /api/v1/health/live` — Returns HTTP 200 `{"status": "ok", "service": "sentinel-ai"}`.
  - `GET /api/v1/health/ready` — Returns HTTP 200 with active provider status and DB health.
- **Lifespan Management:**
  - Startup: Automatically calls `init_db()` creating tables and prepares artifact directory.
  - Shutdown: Safely closes SIEM HTTP connections and database engine pools.

---

## 4. Frontend Configuration & Vercel Alignment

- **Framework:** React 19 + TypeScript + Vite.
- **Build Output Directory:** `dist`.
- **Build Command:** `npm run build` (`tsc -b && vite build`).
- **Dev Command:** `npm run dev`.
- **API URL Binding:** Currently `frontend/src/services/api.ts` defines `const API_BASE = '/api/v1'`.
  - For Vercel, this must be made configurable via `import.meta.env.VITE_API_BASE_URL` so browser requests can hit Render directly, or routed through Vercel rewrites.

---

## 5. Database & Migration Configuration

- **ORM:** SQLAlchemy 2.0 async engine (`create_async_engine`).
- **Driver:** `asyncpg` for PostgreSQL; `aiosqlite` for SQLite.
- **Alembic Configuration:** `backend/alembic/env.py` dynamically injects `Settings.database_url`.
- **Current Migration:** `7dc240726238_initial_sentinel_schema.py` covering all 9 required tables:
  1. `users` (UUID primary key, email, bcrypt hash, role)
  2. `conversations` (UUID, user ownership, provider, data_mode)
  3. `messages` (UUID, conversation relation, role, structured metadata)
  4. `investigations` (UUID, query_spec JSONB, risk_score, risk_level)
  5. `query_executions` (UUID, duration_ms, redacted compiled query)
  6. `evidence_references` (UUID, event_id, document_id, snapshot JSONB)
  7. `findings` (UUID, classification, severity, evidence IDs)
  8. `reports` (UUID, artifact_path, sha256 checksum, status)
  9. `audit_events` (UUID, action, user_id, timestamp)
- **Supabase Migration Command:**
  ```bash
  alembic -c backend/alembic.ini upgrade head
  ```

---

## 6. LLM Configuration & Supported Providers

- **Client Class:** `LLMClient` in `backend/app/nlp/llm_client.py`.
- **Protocol:** Standard OpenAI-compatible `/chat/completions` REST API with JSON object response format.
- **Compatible Providers:**
  - OpenAI (`https://api.openai.com/v1`, models: `gpt-4o`, `gpt-4o-mini`)
  - Google Gemini OpenAI Endpoint (`https://generativelanguage.googleapis.com/v1beta/openai/`, models: `gemini-1.5-pro`, `gemini-1.5-flash`)
  - Groq (`https://api.groq.com/openai/v1`, models: `llama-3.3-70b-versatile`)
  - OpenRouter (`https://openrouter.ai/api/v1`)
  - Ollama (`http://localhost:11434/v1` for local hosting)
- **Fallback Guarantee:** If `LLM_API_KEY` is omitted or an external call fails, the multi-agent workflow gracefully falls back to the deterministic local intent planner. No downtime or failed turns occur if the LLM provider experiences an outage.

---

## 7. SIEM Provider Configurations

1. **Synthetic Mode (`synthetic`):**
   - Active by default.
   - Loads 94 reproducible events across 10 security scenarios.
   - All responses, headers, and reports prominently carry the `SYNTHETIC DATA` disclosure.
2. **Wazuh Adapter (`wazuh`):**
   - Implements `ProviderInterface`.
   - Requires `WAZUH_API_URL`, `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`.
   - Acquires and caches JWT tokens from `/security/user/authenticate`.
   - Queries `/alerts` and normalizes alerts into canonical ECS `SecurityEvent`.
3. **Elasticsearch 8.x Adapter (`elasticsearch`):**
   - Implements `ProviderInterface`.
   - Requires `ELASTICSEARCH_URL`, plus `ELASTICSEARCH_API_KEY` or basic auth credentials.
   - Restricts queries to `ELASTICSEARCH_INDEX_ALLOWLIST` (defaults to `logs-*,wazuh-alerts-*`).
   - Reports partial shard failures honestly (`is_partial=True`).

---

## 8. Security & Compliance Checklist

| Area | Status | Verified Implementation |
|---|---|---|
| **Secret Leakage** | Pass | No secrets committed. `.env` listed in `.gitignore`. |
| **Authentication** | Pass | JWT HS256 tokens with configurable expiry; bcrypt password hashing. |
| **Authorization (RBAC)** | Pass | Role-based permissions (`admin`, `analyst`, `auditor`). |
| **SIEM Query Safety** | Pass | Mandatory `QueryValidator` rejecting script fields, unapproved fields, and out-of-bound time windows. |
| **Prompt Injection Defense** | Pass | Log content is strictly encapsulated as inert JSON data, never interpreted as instructions. |
| **CSV Formula Injection** | Pass | All CSV string fields prefixed with single quote if starting with `=`, `+`, `-`, `@`, `\t`. |
| **PDF Integrity** | Pass | Mandatory watermarking, evidence tracing table, and SHA-256 integrity hash. |
| **CORS Policy** | Pass | Configurable allowed origins list (`CORS_ORIGINS`). |
