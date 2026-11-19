# SENTINEL AI — Deployment Blockers & Render/Vercel Constraints Analysis

This document details all discovered deployment blockers, cloud tier limitations, and actionable remediation steps for deploying SENTINEL AI to **Render** (Backend), **Supabase** (Database), and **Vercel** (Frontend).

---

## Blocker Matrix

| ID | Issue | Severity | Target | Status | Remediated in Repo? |
|---|---|---|---|---|---|
| **BLK-01** | Frontend hardcoded API route (`/api/v1`) | **CRITICAL** | Vercel | Needs Code Update | Yes (ready to patch) |
| **BLK-02** | Missing `requirements.txt` for Render Python builder | **HIGH** | Render | Needs File Creation | Yes (ready to create) |
| **BLK-03** | Ephemeral disk on Render wipes PDF/CSV report artifacts | **HIGH** | Render Free Tier | Architectural Constraint | Documented + Workaround |
| **BLK-04** | Render Free Tier 15-minute inactivity sleep (Cold starts) | **MEDIUM** | Render Free Tier | Operational Constraint | Documented |
| **BLK-05** | Supabase `asyncpg` connection pooler & prepared statements | **MEDIUM** | Supabase | Configuration Required | Documented |
| **BLK-06** | Wazuh / Elasticsearch private network ingress | **MEDIUM** | SIEM / Render | Network Constraint | Documented + Phased Path |

---

## Detailed Breakdown & Remediation Plans

### BLK-01: Frontend Hardcoded API Route (CRITICAL)
- **Problem:** `frontend/src/services/api.ts` line 9 defines:
  ```typescript
  const API_BASE = '/api/v1'
  ```
  In local development, Vite proxies `/api` to `http://localhost:8000`. When deployed to Vercel at `https://your-app.vercel.app`, any call to `/api/v1/...` attempts to hit the Vercel static host itself, resulting in HTTP 404 errors.
- **Remediation:**
  1. Update `frontend/src/services/api.ts` to:
     ```typescript
     const API_BASE = `${import.meta.env.VITE_API_BASE_URL || ''}/api/v1`
     ```
  2. Create `frontend/vercel.json` with client-side SPA routing rewrites:
     ```json
     {
       "rewrites": [
         { "source": "/(.*)", "destination": "/index.html" }
       ]
     }
     ```
  3. Set `VITE_API_BASE_URL=https://your-backend.onrender.com` in Vercel settings.

---

### BLK-02: Missing `requirements.txt` for Render Builder (HIGH)
- **Problem:** Render's default native Python environment executes:
  ```bash
  pip install -r requirements.txt
  ```
  The repository currently only provides `pyproject.toml` with optional extras for `langgraph` and `elasticsearch`. Attempting to deploy on Render using standard build instructions will fail with `ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements.txt'`.
- **Remediation:**
  Create a production-ready `requirements.txt` containing all runtime dependencies (FastAPI, Uvicorn, LangGraph, LangChain-Core, SQLAlchemy, Asyncpg, Elasticsearch, ReportLab, etc.) locked to compatible versions.

---

### BLK-03: Ephemeral File Storage on Render Free Tier (HIGH)
- **Problem:** Render Web Services on the free tier utilize an **ephemeral disk**.
  - When the web service goes to sleep or restarts, any files generated and stored in `./artifacts/` (PDF, CSV, JSON reports) will be deleted.
  - While report metadata remains intact in the Supabase PostgreSQL database, downloading an earlier report after a service restart will return `HTTP 404: Report file artifact missing from disk`.
- **Operational Impact:**
  - Generating and downloading reports immediately within an active session works perfectly.
  - Historical downloads after an instance restart will fail unless persistent storage is used.
- **Recommended Solutions:**
  - **Phase 1 (Initial Demo):** Retain local `./artifacts` storage; download generated reports immediately upon generation.
  - **Phase 2 (Production Hardening):** Stream report bytes directly to a **Supabase Storage Bucket** or **AWS S3 / Cloudflare R2** object store, storing the object URL or blob key in the `reports` database table.

---

### BLK-04: Render Free Tier Inactivity Sleep & Cold Starts (MEDIUM)
- **Problem:** Free Render services spin down to zero instances after 15 minutes of inactivity.
- **Operational Impact:**
  - The first HTTP request after idle time takes **30–60 seconds** while the container starts.
  - Subsequent requests respond with normal sub-second latencies.
- **Remediation:**
  - The SOC analyst should be aware that the initial page load or health check will take ~45s if idle.
  - A free uptime monitor (e.g. UptimeRobot or Cron-job.org) can ping `/api/v1/health/live` every 10 minutes to keep the instance warm if desired.

---

### BLK-05: Supabase `asyncpg` Connection Mode & SSL (MEDIUM)
- **Problem:** Supabase offers two connection modes:
  1. **Direct Connection (Port 5432):** In modern Supabase projects, direct connections resolve via IPv6. If Render's free tier runtime cannot reach IPv6, direct connection fails.
  2. **Transaction Pooler (Port 6543):** Supported over IPv4, but PgBouncer does not support prepared statements with `asyncpg` by default.
- **Remediation:**
  - In Supabase, obtain the **Connection Pooling** connection string with **Session Mode** (Port 5432) or **Transaction Mode** (Port 6543).
  - If using Transaction Mode with `asyncpg`, append `?prepared_statement_cache_size=0` to the `DATABASE_URL` in Render environment variables:
    ```text
    DATABASE_URL=postgresql+asyncpg://postgres.xxxx:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres?prepared_statement_cache_size=0
    ```

---

### BLK-06: Live SIEM Network Reachability (MEDIUM)
- **Problem:** A local Wazuh Manager or Elasticsearch instance hosted on a private workstation or home network (`localhost:55000`, `192.168.x.x`) cannot be reached by Render's public cloud servers.
- **Remediation:**
  - **Initial Step:** Deploy the application with `SIEM_PROVIDER=synthetic` and `SENTINEL_DATA_MODE=synthetic`. This verifies the full cloud deployment pipeline (Frontend on Vercel ↔ Backend on Render ↔ Database on Supabase) without network dependencies.
  - **Next Step:** When ready to connect live Wazuh, expose the Wazuh Manager API securely using a reverse proxy with TLS, a public IP with strict IP allowlisting (Render egress IP or firewall rule), or a secure tunneling service (Cloudflare Tunnel).
