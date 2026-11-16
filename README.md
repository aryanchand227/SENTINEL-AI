# SENTINEL AI

**Project SIH25173 — Conversational SIEM Assistant for Investigation and Automated Threat Reporting using NLP**

SENTINEL AI enables a Security Operations Centre (SOC) analyst to investigate security telemetry using natural language. It interprets analyst inquiries, creates a typed and validated query plan (Sentinel Query Specification - SQS), executes read-only searches against security data providers, correlates evidence, and produces verifiable incident reports.

---

## Operating Modes

1. **Mode A — Synthetic Provider (Active / Verified):**
   - Deterministic, reproducible security events generated from a fixed seed.
   - Covers 10 core attack & benign scenarios (Appendix B): SSH brute force, privilege escalation, suspicious PowerShell, file integrity monitoring, port scans, malware detection, and routine benign activity.
   - Persistent `SYNTHETIC DATA` watermark in UI and all exported reports.
2. **Mode B — Elasticsearch Provider (Phase 2):** Read-only searches against approved index patterns.
3. **Mode C — Wazuh Provider (Phase 2):** Documented endpoint security alert integration.

---

## System Architecture

```text
Analyst (React + Vite)
      │
      ▼
FastAPI API Gateway (/api/v1)
      │
      ├─► Auth & RBAC (JWT, bcrypt)
      ├─► Intent Planner & Multi-Turn Context Resolver
      ├─► Deterministic Query Validator (Bounds, Allowlist, Type Safety)
      ├─► Query Compiler (SQS -> Provider SearchRequest)
      │
      ▼
SIEM Provider Interface
      ├─► Synthetic Provider (94 deterministic scenario events)
      ├─► Elasticsearch Provider (Planned)
      └─► Wazuh Provider (Planned)
      │
      ▼
Persistence & Reporting
      ├─► SQLAlchemy 2.x async ORM (PostgreSQL / SQLite)
      ├─► Alembic Migrations
      └─► ReportLab PDF, JSON & CSV Export (with formula-injection defense)
```

---

## Quickstart

### Prerequisites
- Python 3.12+
- Node.js 20+ & npm
- `uv` package manager (optional, recommended)

### Backend Setup & Startup
```powershell
# Create and activate virtual environment
uv venv .venv
.venv\Scripts\activate

# Install dependencies
uv pip install -e ".[dev]"

# Run database migrations
cd backend
alembic upgrade head
cd ..

# Run tests
pytest backend/tests/ -v

# Start backend server
uvicorn backend.app.main:app --reload --port 8000
```

### Frontend Setup & Startup
```powershell
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173`.

---

## Verification & Test Results
- **Pytest:** 75/75 unit & integration tests passing.
- **Ruff:** 0 errors (100% compliant).
- **Mypy:** 0 type errors across 40 source files.
- **Frontend Build:** Clean Vite production build.
