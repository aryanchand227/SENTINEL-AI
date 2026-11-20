# SENTINEL AI — Deployment Environment Variables Specification

This document provides the authoritative template for environment variables across all deployment targets (**Render Backend**, **Vercel Frontend**, and **Local Development**).

All backend variable names match the typed `Settings` model defined in `backend/app/core/config.py`.

---

## 1. Render Backend (Web Service Environment Variables)

Configure these variables in your **Render Dashboard → Your Web Service → Environment**:

| Variable Name | Required | Default in Code | Example Production Value | Description |
|---|---|---|---|---|
| `APP_ENV` | **Yes** | `development` | `production` | Switches environment mode. In production, auto-documentation (`/docs`, `/redoc`) is disabled. |
| `APP_NAME` | No | `SENTINEL_AI` | `SENTINEL_AI` | Name identifier for logs and metadata. |
| `API_V1_PREFIX` | No | `/api/v1` | `/api/v1` | URL routing prefix for API endpoints. |
| `APP_SECRET_KEY` | **Yes** | — | *(Generate random 32+ char string)* | Core application cryptographic secret. |
| `JWT_SECRET_KEY` | **Yes** | — | *(Generate random 32+ char string)* | HMAC secret key used for signing JWT access tokens. |
| `JWT_ALGORITHM` | No | `HS256` | `HS256` | JWT signing algorithm. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `30` | `60` | Lifetime of issued analyst access tokens in minutes. |
| `CORS_ORIGINS` | **Yes** | `http://localhost:5173` | `https://your-frontend.vercel.app` | Comma-separated list of allowed frontend origins. |
| `DATABASE_URL` | **Yes** | `sqlite+aiosqlite:///./sentinel_dev.db` | `postgresql+asyncpg://postgres:[PASSWORD]@[HOST]:[PORT]/postgres` | Async database connection URL pointing to Supabase PostgreSQL. |
| `SIEM_PROVIDER` | **Yes** | `synthetic` | `synthetic` | Active SIEM provider: `synthetic`, `wazuh`, or `elasticsearch`. |
| `SENTINEL_DATA_MODE` | **Yes** | `synthetic` | `synthetic` | Data label mode: `synthetic` or `live`. Must match `synthetic` for demo. |
| `LLM_PROVIDER` | No | `cloud` | `groq` | LLM runtime adapter: `groq`, `cloud`, or `synthetic`. |
| `GROQ_API_KEY` | Conditional | `""` | `gsk_...` | Groq Cloud API key. Required when `LLM_PROVIDER=groq`. |
| `GROQ_MODEL` | No | `openai/gpt-oss-20b` | `openai/gpt-oss-20b` | Groq model identifier (e.g. `openai/gpt-oss-20b`, `llama-3.3-70b-versatile`). |
| `LLM_API_KEY` | No | `""` | `sk-...` | Secret API key for generic cloud LLM. Automatically recognized as fallback for Groq if starts with `gsk_`. |
| `LLM_BASE_URL` | No | `""` | `https://api.openai.com/v1` | Base URL for OpenAI-compatible completions. |
| `LLM_TIMEOUT_SECONDS` | No | `30` | `30` | Timeout threshold for LLM requests in seconds. |
| `LLM_MAX_RETRIES` | No | `2` | `2` | Maximum retry attempts for transient API failures. |
| `MAX_QUERY_WINDOW_HOURS` | No | `168` | `168` | Upper bound for time range queries (168h = 7 days). |
| `MAX_QUERY_PAGE_SIZE` | No | `500` | `500` | Maximum event records returned in a single query. |
| `MAX_AGGREGATION_BUCKETS` | No | `100` | `100` | Maximum aggregation buckets allowed in query plan. |
| `REPORT_STORAGE_PATH` | No | `./artifacts` | `./artifacts` | Local directory for generated report artifacts. |
| `APP_LOG_LEVEL` | No | `INFO` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

### Live Wazuh Integration Variables (When connecting Wazuh)
| Variable Name | Required if Wazuh | Description |
|---|---|---|
| `WAZUH_API_URL` | Yes | HTTPS URL of your Wazuh Manager API (e.g. `https://wazuh.yourdomain.com:55000`). |
| `WAZUH_API_USERNAME` | Yes | Username for Wazuh API (e.g. `wazuh-api-user`). |
| `WAZUH_API_PASSWORD` | Yes | Password for Wazuh API. |
| `WAZUH_API_VERSION` | No | Wazuh API version string (optional). |

### Live Elasticsearch Integration Variables (When connecting Elasticsearch)
| Variable Name | Required if ES | Description |
|---|---|---|
| `ELASTICSEARCH_URL` | Yes | HTTPS URL of your Elasticsearch cluster (e.g. `https://es.yourdomain.com:9200`). |
| `ELASTICSEARCH_API_KEY` | Optional | API Key authentication (preferred over username/password). |
| `ELASTICSEARCH_USERNAME` | Optional | Username for basic authentication. |
| `ELASTICSEARCH_PASSWORD` | Optional | Password for basic authentication. |
| `ELASTICSEARCH_INDEX_ALLOWLIST` | No | Comma-separated pattern list (default: `logs-*,wazuh-alerts-*`). |

---

## 2. Vercel Frontend (Environment Variables)

Configure this in your **Vercel Project Settings → Environment Variables**:

| Variable Name | Required | Example Value | Description |
|---|---|---|---|
| `VITE_API_BASE_URL` | **Yes** | `https://sentinel-ai-backend.onrender.com` | Base URL of the deployed Render backend without trailing slash. |

> [!WARNING]
> Any variable prefixed with `VITE_` is bundled into the client-side JavaScript code and is publicly readable by anyone inspecting the website in DevTools. Never place API keys, database passwords, or JWT secrets in Vercel environment variables.

---

## 3. How to Generate Cryptographic Secrets

Generate strong, cryptographically secure 64-character hexadecimal keys for `APP_SECRET_KEY` and `JWT_SECRET_KEY`:

```bash
# Using Python
python -c "import secrets; print(secrets.token_hex(32))"
```

Run this command twice to generate distinct secrets for `APP_SECRET_KEY` and `JWT_SECRET_KEY`.
