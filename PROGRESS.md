# PROGRESS.md

## Project identity
- **Project:** SENTINEL AI / SIH25173
- **Repository:** d:\CSE_431
- **Branch:** main
- **Last updated (UTC):** 2026-11-16T13:00Z
- **Current coding agent:** Antigravity (Claude Opus 4.6 Thinking)
- **Working directory:** d:\CSE_431
- **Current commit:** (initial — not yet committed)
- **Working tree status:** clean, ready for initial commit

## Current phase and task
- **Phase:** 0 — Repository Discovery and Design Freeze
- **Task ID:** P0-COMPLETE
- **Task:** Repository discovery, environment detection, project scaffold, foundational modules
- **Status:** VERIFIED
- **Objective:** Establish repository, verify environment, create project configuration, core settings, security, health endpoints, and passing tests
- **Dependencies:** Python 3.12+, Node.js, uv
- **Acceptance criteria:**
  - [x] Git initialized
  - [x] Repository state understood — only spec file existed
  - [x] Python 3.12.10, Node v25.8.1, npm 11.11.0, uv 0.11.14 detected
  - [x] Docker NOT available — documented
  - [x] No pre-existing environment variables found
  - [x] AGENTS.md created
  - [x] .gitignore, .env.example, .editorconfig created
  - [x] pyproject.toml with all core dependencies
  - [x] Virtual environment created and 59 packages installed
  - [x] Backend app structure: core/config.py, core/security.py, api/routes/health.py, main.py, lifespan.py
  - [x] 12 unit + integration tests pass

## Completed task checklist
- [x] Phase 0 — Repository discovery
- [ ] Phase 1 — Synthetic vertical slice
- [ ] Phase 2 — Elastic and Wazuh
- [ ] Phase 3 — NLP and query intelligence
- [ ] Phase 4 — Investigation intelligence
- [ ] Phase 5 — Reporting and frontend
- [ ] Phase 6 — Security and deployment

## Files created or modified

| File | Purpose |
|------|---------|
| `AGENTS.md` | Agent instructions with quick reference and frozen stack |
| `PROGRESS.md` | This file — project progress tracker |
| `.gitignore` | Git ignore rules for Python, Node, IDE, secrets |
| `.env.example` | Environment configuration template with safe placeholders |
| `.editorconfig` | Editor configuration for consistent formatting |
| `pyproject.toml` | Python project config: deps, build, pytest, ruff, mypy |
| `backend/__init__.py` | Backend package marker |
| `backend/app/__init__.py` | App package marker |
| `backend/app/main.py` | FastAPI application factory and entry point |
| `backend/app/lifespan.py` | Startup/shutdown lifecycle hooks |
| `backend/app/core/__init__.py` | Core package marker |
| `backend/app/core/config.py` | Typed Settings (Pydantic v2 BaseSettings) |
| `backend/app/core/security.py` | JWT creation/decode, bcrypt password hashing, UserRole |
| `backend/app/api/__init__.py` | API package marker |
| `backend/app/api/v1.py` | API v1 router aggregation |
| `backend/app/api/routes/__init__.py` | Routes package marker |
| `backend/app/api/routes/health.py` | /health/live and /health/ready endpoints |
| `backend/app/schemas/__init__.py` | Schemas package marker |
| `backend/app/domain/__init__.py` | Domain package marker |
| `backend/app/siem/__init__.py` | SIEM package marker |
| `backend/app/query/__init__.py` | Query engine package marker |
| `backend/tests/__init__.py` | Tests package marker |
| `backend/tests/unit/__init__.py` | Unit tests marker |
| `backend/tests/unit/test_config.py` | 5 tests for Settings (defaults, env vars, modes) |
| `backend/tests/unit/test_security.py` | 5 tests for password hashing and JWT |
| `backend/tests/integration/__init__.py` | Integration tests marker |
| `backend/tests/integration/test_health.py` | 2 tests for health endpoints via HTTPX |
| `artifacts/.gitkeep` | Placeholder for report artifact storage |

## Architecture decisions

| Decision | Rationale | Date | Affected |
|----------|-----------|------|----------|
| Use bcrypt directly instead of passlib | passlib is unmaintained, incompatible with bcrypt 5.x | 2026-11-16 | core/security.py |
| SQLite default for dev/test DB | PostgreSQL not available locally; SQLite for compatible tests per spec | 2026-11-16 | core/config.py |
| Docker deferred | Docker not installed on this machine; compose file to be created later | 2026-11-16 | deployment |

## Environment variables
| Name | Purpose |
|------|---------|
| APP_ENV | development/testing/production mode |
| SIEM_PROVIDER | synthetic/elasticsearch/wazuh |
| SENTINEL_DATA_MODE | synthetic/live data designation |
| DATABASE_URL | Async database connection string |
| JWT_SECRET_KEY | JWT signing secret |
| APP_SECRET_KEY | Application secret |
| ELASTICSEARCH_URL | Elastic endpoint |
| ELASTICSEARCH_INDEX_ALLOWLIST | Comma-separated index patterns |
| WAZUH_API_URL | Wazuh API endpoint |
| LLM_PROVIDER | LLM provider type |
| LLM_API_KEY | LLM API key |
| MAX_QUERY_WINDOW_HOURS | Maximum query time window |
| MAX_QUERY_PAGE_SIZE | Maximum results per page |
| REPORT_STORAGE_PATH | Directory for generated reports |

## Verification ledger

| Command | Date/Time (UTC) | Exit | Summary | Task |
|---------|-----------------|------|---------|------|
| `python --version` | 2026-11-16T12:55Z | 0 | Python 3.12.10 | P0 |
| `node --version` | 2026-11-16T12:55Z | 0 | v25.8.1 | P0 |
| `uv --version` | 2026-11-16T12:56Z | 0 | uv 0.11.14 | P0 |
| `docker --version` | 2026-11-16T12:55Z | 1 | Not installed | P0 |
| `uv pip install -e ".[dev]"` | 2026-11-16T12:59Z | 0 | 59 packages installed | P0 |
| `pytest backend/tests/ -v` (1st run) | 2026-11-16T13:00Z | 1 | 10 passed, 2 failed (passlib/bcrypt compat) | P0 |
| `pytest backend/tests/ -v` (2nd run) | 2026-11-16T13:00Z | 0 | **12 passed** | P0 |

## Known bugs and blockers
- **Docker not available:** Docker is not installed. Docker Compose deployment will require Docker installation. Documented, not blocking dev.
- **No PostgreSQL locally:** Using SQLite for dev/test. PostgreSQL integration tests require a PostgreSQL instance.

## Exact next step
**Phase 1, Task P1.1: Canonical event schema and synthetic event generator**
- Create `backend/app/domain/events.py` — ECS-compatible canonical event model (Pydantic v2, `extra="forbid"`)
- Create `backend/app/siem/provider_interface.py` — Abstract provider contract
- Create `backend/app/siem/synthetic/generator.py` — Deterministic synthetic event generator with fixed seed
- Create `backend/app/siem/synthetic/provider.py` — Synthetic provider implementing the common interface
- Acceptance: generator produces reproducible events covering all 10 attack scenarios; provider returns filtered/aggregated results; unit tests pass

## Handover summary
- **What works:** Git repo initialized, backend project structured, Settings loaded from env, JWT auth, bcrypt passwords, health endpoints returning correct synthetic-mode status, 12 tests green
- **What was last verified:** `pytest backend/tests/ -v` — 12 passed (2026-11-16T13:00Z)
- **What is incomplete:** All of Phase 1+ (event schema, synthetic provider, SQS, API routes, frontend, everything else)
- **External services required:** PostgreSQL (for prod/integration), Elasticsearch (Phase 2), Wazuh (Phase 2), LLM API (Phase 3)
- **User approval required:** None at this time
