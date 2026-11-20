# SENTINEL AI — Backend API Inventory

**Target Environment:** FastAPI 0.115+ / Python 3.12+  
**API Version:** v1 (`/api/v1`)  
**Audit Date:** 2026-11-20  
**Auditor:** Senior Backend QA Engineer  
**Specification Baseline:** SIH25173 Master System Prompt (`SENTINEL_AI_Master_System_Prompt_AGENTS.md`)

---

## 1. Executive Summary

A comprehensive programmatic and static inspection of the SENTINEL AI FastAPI router tree (`backend/app/api/`) identified **15 registered API endpoints** across 6 domain routers.

### Router Breakdown

| Router Prefix | Domain / Responsibility | Registered Endpoints | Auth Required |
| :--- | :--- | :---: | :---: |
| `/api/v1/health` | Service liveness, readiness, & database latency | 3 | Public |
| `/api/v1/auth` | Analyst authentication & current profile | 2 | 1 Public, 1 Protected |
| `/api/v1` (conversations) | Workspace management & multi-turn investigation | 4 | 4 Protected |
| `/api/v1/queries` | SQS query preview, validation & SIEM execution | 2 | 2 Protected |
| `/api/v1/providers` | SIEM provider connectivity, health & schema mapping | 1 | 1 Protected |
| `/api/v1` (reports) | Report generation, metadata & verified artifact download | 3 | 3 Protected |
| **Total** | | **15** | **11 Protected, 4 Public** |

---

## 2. Comprehensive Registered Endpoints Inventory

### 2.1 Health & Diagnostic Endpoints (`tags: ["health"]`)

#### 1. `GET /api/v1/health/live`
- **Operation ID:** `liveness_api_v1_health_live_get`
- **Auth Required:** No (Public probe)
- **Summary:** Process Liveness Probe
- **Purpose:** Verifies that the FastAPI process is running and able to handle HTTP events. Returns immediate HTTP 200 without touching downstream dependencies.
- **Request Parameters / Body:** None
- **Response Model:** `LivenessResponse` (`status="ok"`, `service="sentinel-ai"`)
- **Implementation Status:** **Implemented**

#### 2. `GET /api/v1/health/ready`
- **Operation ID:** `readiness_api_v1_health_ready_get`
- **Auth Required:** No (Public probe)
- **Summary:** Dependency Readiness Check
- **Purpose:** Validates readiness of critical application dependencies before traffic routing. Executes an active database `SELECT 1` ping and reports the status of the configured SIEM provider.
- **Request Parameters / Body:** None
- **Response Model:** `ReadinessResponse` (`status="ready"|"degraded"`, `provider=str`, `data_mode=str`, `checks={"database": "ok", "provider": "ok"}`)
- **Implementation Status:** **Implemented**

#### 3. `GET /api/v1/health/db`
- **Operation ID:** `database_health_api_v1_health_db_get`
- **Auth Required:** No (Public probe)
- **Summary:** Dedicated Database Health & Latency Probe
- **Purpose:** Executes an explicit `SELECT 1` over the active SQLAlchemy AsyncEngine session pool, timing query latency and reporting connection health and dialect (`postgresql` / `sqlite`).
- **Request Parameters / Body:** None
- **Response Model:** `DatabaseHealthResponse` (`status="healthy"|"unhealthy"`, `database=str`, `latency_ms=float`, `error=str|None`)
- **Implementation Status:** **Implemented**

---

### 2.2 Authentication & Identity Endpoints (`tags: ["auth"]`)

#### 4. `POST /api/v1/auth/login`
- **Operation ID:** `login_api_v1_auth_login_post`
- **Auth Required:** No (Public endpoint)
- **Summary:** Analyst Login & JWT Issuance
- **Purpose:** Authenticates analyst credentials against bcrypt-hashed passwords. Verifies account active status and issues a signed HS256 JWT access token with user ID and role claims.
- **Request Body:** `LoginRequest` (`email: EmailStr`, `password: str`, `extra="forbid"`)
- **Response Model:** `TokenResponse` (`access_token: str`, `token_type="bearer"`, `user_id: str`, `email: str`, `role: str`, `display_name: str`)
- **Error Codes:** `401 Unauthorized` (invalid email or password), `403 Forbidden` (account deactivated), `422 Unprocessable Entity` (malformed payload)
- **Implementation Status:** **Implemented**

#### 5. `GET /api/v1/auth/me`
- **Operation ID:** `me_api_v1_auth_me_get`
- **Auth Required:** Yes (`HTTPBearer` Header: `Authorization: Bearer <token>`)
- **Summary:** Current Analyst Profile
- **Purpose:** Resolves and returns identity metadata for the currently authenticated security analyst.
- **Request Parameters / Body:** None
- **Response Model:** `UserResponse` (`id: str`, `email: str`, `display_name: str`, `role: str`, `is_active: bool`)
- **Error Codes:** `401 Unauthorized` (missing, invalid, expired token or inactive account)
- **Implementation Status:** **Implemented**

---

### 2.3 Conversational Investigation Endpoints (`tags: ["conversations"]`)

#### 6. `POST /api/v1/conversations`
- **Operation ID:** `create_conversation_api_v1_conversations_post`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Create Investigation Workspace
- **Purpose:** Initializes a new persistent conversation workspace bound to the authenticated analyst for multi-turn incident investigations.
- **Request Body:** `ConversationCreateRequest` (`title: str`, `provider: str`, `data_mode: str`)
- **Response Model:** `ConversationResponse` (`id: str`, `user_id: str`, `title: str`, `provider: str`, `data_mode: str`, `created_at: datetime`, `updated_at: datetime`)
- **Implementation Status:** **Implemented**

#### 7. `GET /api/v1/conversations`
- **Operation ID:** `list_conversations_api_v1_conversations_get`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** List Analyst Conversations
- **Purpose:** Lists all conversation workspaces owned by the authenticated analyst, ordered by `updated_at` descending.
- **Request Parameters / Body:** None
- **Response Model:** `list[ConversationResponse]`
- **Implementation Status:** **Implemented**

#### 8. `GET /api/v1/conversations/{conv_id}`
- **Operation ID:** `get_conversation_api_v1_conversations__conv_id__get`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Get Conversation Details & Message History
- **Purpose:** Retrieves conversation metadata and chronological message history (user queries and assistant responses with structured metadata). Enforces strict multi-tenant ownership check.
- **Path Parameter:** `conv_id: str`
- **Response Model:** `ConversationDetailResponse` (`conversation: ConversationResponse`, `messages: list[MessageItem]`)
- **Error Codes:** `404 Not Found` (conversation missing or owned by different analyst)
- **Implementation Status:** **Implemented**

#### 9. `POST /api/v1/chat`
- **Operation ID:** `chat_turn_api_v1_chat_post`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Conversational Investigation Turn Execution
- **Purpose:** Core multi-agent LangGraph workflow execution for Section 36 demonstration flow:
  1. Validates conversation ownership.
  2. Resolves multi-turn context (e.g., previously identified suspect accounts or target entities).
  3. Executes LangGraph pipeline (`plan_intent` -> `validate_query` -> `execute_query` -> `analyze_events` -> `synthesize_response`).
  4. Records `Message`, `QueryExecution`, `EvidenceReference`, and `Finding` records transactionally.
  5. Returns structured assistant response with follow-up suggestions and evidence citations.
- **Request Body:** `ChatTurnRequest` (`conversation_id: str`, `message: str`, `investigation_id: str | None`)
- **Response Model:** `ChatTurnResponse` (`request_id: str`, `conversation_id: str`, `investigation_id: str`, `assistant_message: str`, `query_spec: SentinelQuerySpec | None`, `validation_status: str`, `result_count: int`, `evidence_ids: list[str]`, `findings: list[FindingItem]`, `data_mode: str`, `follow_up_suggestions: list[str]`)
- **Error Codes:** `400 Bad Request` (query validation rejected), `404 Not Found` (conversation not owned)
- **Implementation Status:** **Implemented**

---

### 2.4 Query Validation & SIEM Execution Endpoints (`tags: ["queries"]`)

#### 10. `POST /api/v1/queries/preview`
- **Operation ID:** `preview_query_api_v1_queries_preview_post`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Validate SQS and Preview Query Compilation
- **Purpose:** Validates a `SentinelQuerySpec` (SQS) against the Approved Field Registry, time-window constraints, and syntax rules without querying the SIEM. Compiles the SQS to the provider-specific query structure for analyst preview.
- **Request Body:** `QueryPreviewRequest` (`spec: SentinelQuerySpec`)
- **Response Model:** `QueryPreviewResponse` (`is_valid: bool`, `errors: list[ValidationErrorDetail]`, `warnings: list[str]`, `compiled_request: dict | None`, `provider: str`, `data_mode: str`)
- **Implementation Status:** **Implemented**

#### 11. `POST /api/v1/queries/execute`
- **Operation ID:** `execute_query_api_v1_queries_execute_post`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Validate, Compile, and Execute SIEM Search
- **Purpose:** Strictly validates the SQS specification before executing a read-only search against the configured provider (`synthetic`, `elasticsearch`, or `wazuh`). Records an immutable `QueryExecution` record and returns normalized ECS events and aggregations.
- **Request Body:** `QueryExecuteRequest` (`spec: SentinelQuerySpec`, `investigation_id: str | None`)
- **Response Model:** `QueryExecuteResponse` (`execution_id: str`, `provider: str`, `data_mode: str`, `metadata: SearchResultMetadata`, `events: list[dict]`, `aggregations: list[AggregationResult]`)
- **Error Codes:** `400 Bad Request` (validation failed before query execution)
- **Implementation Status:** **Implemented**

---

### 2.5 SIEM Provider Status Endpoints (`tags: ["providers"]`)

#### 12. `GET /api/v1/providers/status`
- **Operation ID:** `get_provider_status_api_v1_providers_status_get`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Provider Connectivity, Health, & Field Mappings
- **Purpose:** Performs a live health check on the active SIEM provider, reporting connectivity status, remote cluster version, synthetic mode flag, and field translation mappings.
- **Request Parameters / Body:** None
- **Response Model:** `ProviderStatusResponse` (`provider: str`, `data_mode: str`, `is_synthetic: bool`, `health: ProviderHealthResult`, `field_mappings: dict[str, str]`)
- **Implementation Status:** **Implemented**

---

### 2.6 Incident Reporting Endpoints (`tags: ["reports"]`)

#### 13. `POST /api/v1/investigations/{investigation_id}/reports`
- **Operation ID:** `generate_report_api_v1_investigations__investigation_id__reports_post`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Generate Immutable Incident Report Artifact
- **Purpose:** Generates a verifiable threat report artifact (PDF, JSON, or CSV) from verified investigation findings and evidence snapshots:
  - **PDF:** Generated via ReportLab with mandatory synthetic watermark in test mode.
  - **JSON:** Machine-readable export with findings, evidence, and audit metadata.
  - **CSV:** Evidence table export with formula injection defense (`escape_csv_field`).
  - Computes cryptographic SHA-256 hash and records the report in the `reports` table.
- **Path Parameter:** `investigation_id: str`
- **Request Body:** `GenerateReportRequest` (`format: "pdf" | "json" | "csv"`, `title: str`)
- **Response Model:** `ReportResponse` (`id: str`, `investigation_id: str`, `user_id: str`, `format: str`, `status: str`, `data_mode: str`, `artifact_path: str`, `sha256: str`, `download_url: str`, `created_at: datetime`)
- **Error Codes:** `404 Not Found` (investigation not found or access denied)
- **Implementation Status:** **Implemented**

#### 14. `GET /api/v1/reports/{report_id}`
- **Operation ID:** `get_report_metadata_api_v1_reports__report_id__get`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Retrieve Report Metadata & Verification Checksum
- **Purpose:** Returns report status, SHA-256 checksum, file path, and download URL for an authorized analyst.
- **Path Parameter:** `report_id: str`
- **Response Model:** `ReportResponse`
- **Error Codes:** `404 Not Found` (report does not exist or user mismatch)
- **Implementation Status:** **Implemented**

#### 15. `GET /api/v1/reports/{report_id}/download`
- **Operation ID:** `download_report_api_v1_reports__report_id__download_get`
- **Auth Required:** Yes (`HTTPBearer`)
- **Summary:** Download Verified Report Artifact
- **Purpose:** Serves the generated artifact as a `FileResponse` with correct MIME headers (`application/pdf`, `application/json`, `text/csv`) and attachment disposition after ownership verification.
- **Path Parameter:** `report_id: str`
- **Response:** Binary stream / File
- **Error Codes:** `404 Not Found` (report unauthorized or file missing on disk)
- **Implementation Status:** **Implemented**

---

## 3. Endpoints Status Classification

### 3.1 Fully Implemented & Verified (15 Endpoints)
All 15 endpoints listed above are fully implemented, connected to database persistence and SIEM services, and verified via automated integration tests:
1. `GET /api/v1/health/live`
2. `GET /api/v1/health/ready`
3. `GET /api/v1/health/db`
4. `POST /api/v1/auth/login`
5. `GET /api/v1/auth/me`
6. `POST /api/v1/conversations`
7. `GET /api/v1/conversations`
8. `GET /api/v1/conversations/{conv_id}`
9. `POST /api/v1/chat`
10. `POST /api/v1/queries/preview`
11. `POST /api/v1/queries/execute`
12. `GET /api/v1/providers/status`
13. `POST /api/v1/investigations/{investigation_id}/reports`
14. `GET /api/v1/reports/{report_id}`
15. `GET /api/v1/reports/{report_id}/download`

### 3.2 Endpoints Missing by Design (Out of Current Scope)
The following endpoints are omitted in accordance with the Phase 1-4 minimal footprint specification:
- `POST /api/v1/auth/register`: User provisioning is intended to be administrative or seeded; self-registration is omitted to prevent unauthorized access to SOC tooling.
- `POST /api/v1/auth/refresh`: Refresh token exchange is not implemented; JWT tokens expire cleanly per `access_token_expire_minutes`.
- `DELETE /api/v1/conversations/{conv_id}`: Hard deletion of workspaces from the API is deferred to preserve audit logs.
- Direct CRUD endpoints for `investigations`, `findings`, `evidence_references`, and `audit_events`: These entities are managed implicitly through the chat workflow (`/api/v1/chat`) and reporting pipeline (`/api/v1/investigations/{id}/reports`) rather than through public generic REST mutations.

---

## 4. Security & Access Control Matrix

| Endpoint | Auth Method | Required Scope / Role | Multi-tenant Ownership Enforcement |
| :--- | :---: | :---: | :---: |
| `/api/v1/health/*` | None | Public | N/A |
| `/api/v1/auth/login` | None | Public | N/A |
| `/api/v1/auth/me` | Bearer JWT | Any active role | Self-profile |
| `/api/v1/conversations` (POST) | Bearer JWT | Analyst+ | Current user ID injected |
| `/api/v1/conversations` (GET) | Bearer JWT | Analyst+ | Filtered by `user_id == current_user.id` |
| `/api/v1/conversations/{id}` | Bearer JWT | Analyst+ | Verified `user_id == current_user.id` |
| `/api/v1/chat` | Bearer JWT | Analyst+ | Verified `user_id == current_user.id` |
| `/api/v1/queries/preview` | Bearer JWT | Analyst+ | Read-only simulation |
| `/api/v1/queries/execute` | Bearer JWT | Analyst+ | Read-only query execution & audited |
| `/api/v1/providers/status` | Bearer JWT | Analyst+ | Provider health check |
| `/api/v1/investigations/{id}/reports` | Bearer JWT | Analyst+ | Verified `investigation.user_id == current_user.id` |
| `/api/v1/reports/{id}` | Bearer JWT | Analyst+ | Verified `report.user_id == current_user.id` |
| `/api/v1/reports/{id}/download` | Bearer JWT | Analyst+ | Verified `report.user_id == current_user.id` |
