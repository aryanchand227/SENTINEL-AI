# SENTINEL AI — Phase 6: Frontend to Backend API Contract Mapping

**Document Version:** 1.0.0  
**Project:** SIH25173 — SENTINEL AI  
**Scope:** Complete contract mapping between Frontend SOC Dashboard and FastAPI Backend  
**Base URL:** `http://localhost:8000/api/v1` (configurable via `VITE_API_BASE_URL`)  
**Strict Invariant:** No invented endpoints, no fabricated response fields.

---

## 1. Authentication & Analyst Profile

### 1.1 Analyst Login
- **Frontend Feature:** Login modal / Analyst sign-in
- **Backend Endpoint:** `POST /api/v1/auth/login`
- **Authentication:** None (Public)
- **Request Schema (`LoginRequest`):**
  ```json
  {
    "email": "analyst@sentinel.ai",
    "password": "string"
  }
  ```
- **Response Schema (`TokenResponse`):**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "user_id": "usr-uuid-string",
    "email": "analyst@sentinel.ai",
    "role": "analyst",
    "display_name": "Demo SOC Analyst"
  }
  ```

### 1.2 Current Analyst Profile
- **Frontend Feature:** User status badge in header / sidebar
- **Backend Endpoint:** `GET /api/v1/auth/me`
- **Authentication:** `Bearer <token>` (Auto-seeded to `analyst@sentinel.ai` in dev mode if omitted)
- **Request Schema:** None
- **Response Schema (`UserResponse`):**
  ```json
  {
    "id": "usr-uuid-string",
    "email": "analyst@sentinel.ai",
    "display_name": "Demo SOC Analyst",
    "role": "analyst",
    "is_active": true
  }
  ```

---

## 2. System Health & Provider Status

### 2.1 Backend Readiness Check
- **Frontend Feature:** Navbar operational status indicator & connection error banner
- **Backend Endpoint:** `GET /api/v1/health/ready`
- **Authentication:** None (Public)
- **Request Schema:** None
- **Response Schema (`ReadinessResponse`):**
  ```json
  {
    "status": "ready",
    "provider": "synthetic",
    "data_mode": "synthetic",
    "checks": {
      "database": "ok",
      "provider": "ok"
    }
  }
  ```

### 2.2 Database Latency & Health
- **Frontend Feature:** System Status / Settings tab DB probe
- **Backend Endpoint:** `GET /api/v1/health/db`
- **Authentication:** None (Public)
- **Request Schema:** None
- **Response Schema (`DatabaseHealthResponse`):**
  ```json
  {
    "status": "healthy",
    "database": "postgresql",
    "latency_ms": 12.45,
    "error": null
  }
  ```

### 2.3 Provider Status & ECS Field Mappings
- **Frontend Feature:** Provider configuration card & approved ECS field registry
- **Backend Endpoint:** `GET /api/v1/providers/status`
- **Authentication:** `Bearer <token>`
- **Request Schema:** None
- **Response Schema (`ProviderStatusResponse`):**
  ```json
  {
    "provider": "synthetic",
    "data_mode": "synthetic",
    "is_synthetic": true,
    "health": {
      "provider": "synthetic",
      "status": "healthy",
      "version": "1.0.0",
      "message": "Synthetic provider operational with 94 events across 10 scenarios",
      "checked_at": "2026-11-20T15:30:00Z"
    },
    "field_mappings": {
      "@timestamp": "date",
      "event.id": "keyword",
      "event.category": "keyword",
      "event.action": "keyword",
      "event.outcome": "keyword",
      "event.severity": "integer",
      "user.name": "keyword",
      "source.ip": "ip",
      "destination.ip": "ip",
      "process.name": "keyword",
      "process.command_line": "keyword",
      "file.path": "keyword",
      "file.hash.sha256": "keyword"
    }
  }
  ```

---

## 3. Conversational Investigation & Multi-Turn Chat

### 3.1 Create Investigation Conversation
- **Frontend Feature:** "New Investigation" button / Session initialization
- **Backend Endpoint:** `POST /api/v1/conversations`
- **Authentication:** `Bearer <token>`
- **Request Schema (`ConversationCreateRequest`):**
  ```json
  {
    "title": "Initial SOC Investigation",
    "provider": "synthetic",
    "data_mode": "synthetic"
  }
  ```
- **Response Schema (`ConversationResponse`):**
  ```json
  {
    "id": "conv-uuid",
    "user_id": "usr-uuid",
    "title": "Initial SOC Investigation",
    "provider": "synthetic",
    "data_mode": "synthetic",
    "created_at": "2026-11-20T15:30:00Z",
    "updated_at": "2026-11-20T15:30:00Z"
  }
  ```

### 3.2 List Conversations
- **Frontend Feature:** Investigation history dropdown / Sidebar sessions list
- **Backend Endpoint:** `GET /api/v1/conversations`
- **Authentication:** `Bearer <token>`
- **Request Schema:** None
- **Response Schema:** `list[ConversationResponse]`

### 3.3 Get Conversation Detail & History
- **Frontend Feature:** Reloading session messages & evidence context
- **Backend Endpoint:** `GET /api/v1/conversations/{id}`
- **Authentication:** `Bearer <token>`
- **Request Schema:** None
- **Response Schema (`ConversationDetailResponse`):**
  ```json
  {
    "conversation": {
      "id": "conv-uuid",
      "user_id": "usr-uuid",
      "title": "Initial SOC Investigation",
      "provider": "synthetic",
      "data_mode": "synthetic",
      "created_at": "2026-11-20T15:30:00Z",
      "updated_at": "2026-11-20T15:30:00Z"
    },
    "messages": [
      {
        "id": "msg-uuid",
        "role": "user",
        "content": "Find accounts with failed logins",
        "created_at": "2026-11-20T15:31:00Z",
        "metadata": null
      },
      {
        "id": "msg-uuid-2",
        "role": "assistant",
        "content": "I identified 5 failed authentication attempts...",
        "created_at": "2026-11-20T15:31:02Z",
        "metadata": {
          "suspect_accounts": ["target_user"],
          "evidence_ids": ["syn-auth-001", "syn-auth-002"],
          "result_count": 5,
          "findings": [
            {
              "finding_type": "brute_force",
              "title": "Password Spray / Brute Force",
              "description": "5 consecutive failed logins detected",
              "classification": "observed",
              "severity": "high",
              "confidence_label": "high",
              "evidence_ids": ["syn-auth-001", "syn-auth-002"]
            }
          ]
        }
      }
    ]
  }
  ```

### 3.4 Execute Conversational Turn
- **Frontend Feature:** Chat input execution / Natural Language Investigation
- **Backend Endpoint:** `POST /api/v1/chat`
- **Authentication:** `Bearer <token>`
- **Request Schema (`ChatTurnRequest`):**
  ```json
  {
    "conversation_id": "conv-uuid",
    "message": "Find accounts with failed logins in the last 24 hours.",
    "investigation_id": "inv-uuid-optional"
  }
  ```
- **Response Schema (`ChatTurnResponse`):**
  ```json
  {
    "request_id": "req-123456789abc",
    "conversation_id": "conv-uuid",
    "investigation_id": "inv-uuid",
    "assistant_message": "**Analyst Assessment:** Multiple failed login attempts observed.\n\n### Findings\n...",
    "query_spec": {
      "provider": "synthetic",
      "time_range": {
        "start": "2026-11-15T00:00:00Z",
        "end": "2026-11-17T00:00:00Z"
      },
      "filters": [
        {
          "field": "event.category",
          "operator": "eq",
          "value": "authentication"
        },
        {
          "field": "event.outcome",
          "operator": "eq",
          "value": "failure"
        }
      ],
      "aggregations": [],
      "sort_field": "@timestamp",
      "sort_order": "desc",
      "page_size": 100,
      "intent": "Detect failed logins"
    },
    "validation_status": "valid",
    "result_count": 5,
    "evidence_ids": ["syn-auth-001", "syn-auth-002"],
    "findings": [
      {
        "finding_type": "brute_force",
        "title": "Multiple Failed Authentications",
        "description": "Observed 5 failed logins for jdoe",
        "classification": "observed",
        "severity": "high",
        "confidence_label": "high",
        "evidence_ids": ["syn-auth-001", "syn-auth-002"]
      }
    ],
    "data_mode": "synthetic",
    "follow_up_suggestions": [
      "Did any of those accounts log in successfully afterwards?",
      "Show the top source IP addresses associated with those failures.",
      "Generate a report for this investigation."
    ]
  }
  ```

---

## 4. Security Event Explorer & SQS Execution

### 4.1 Execute SQS Query (Event Explorer & SOC Overview)
- **Frontend Feature:**
  - Overview Dashboard KPI metrics (Total events, severity counts, category counts)
  - Security Event Explorer (Interactive grid, filtering by severity/category/time, raw event inspection)
- **Backend Endpoint:** `POST /api/v1/queries/execute`
- **Authentication:** `Bearer <token>`
- **Request Schema (`QueryExecuteRequest`):**
  ```json
  {
    "spec": {
      "provider": "synthetic",
      "time_range": {
        "start": "2026-11-14T00:00:00Z",
        "end": "2026-11-18T00:00:00Z"
      },
      "filters": [
        {
          "field": "event.severity",
          "operator": "gte",
          "value": 50
        }
      ],
      "aggregations": [
        {
          "type": "terms",
          "field": "event.category",
          "size": 10
        }
      ],
      "sort_field": "@timestamp",
      "sort_order": "desc",
      "page_size": 100,
      "intent": "Explore security events"
    },
    "investigation_id": "inv-uuid-optional"
  }
  ```
- **Response Schema (`QueryExecuteResponse`):**
  ```json
  {
    "execution_id": "exec-uuid",
    "provider": "synthetic",
    "data_mode": "synthetic",
    "metadata": {
      "total_hits": 94,
      "returned_count": 94,
      "is_exact": true,
      "took_ms": 2,
      "warnings": []
    },
    "events": [
      {
        "event": {
          "id": "syn-auth-001",
          "kind": "alert",
          "category": "authentication",
          "type": "start",
          "action": "logon",
          "outcome": "failure",
          "severity": 75,
          "created": "2026-11-16T10:00:00Z",
          "ingested": "2026-11-16T10:00:01Z"
        },
        "@timestamp": "2026-11-16T10:00:00Z",
        "message": "Failed logon attempt for jdoe from 192.168.1.105",
        "user": { "name": "jdoe", "id": "U1001" },
        "source": { "ip": "192.168.1.105", "port": 49152 },
        "destination": { "ip": "10.0.0.5", "port": 445 },
        "host": { "name": "WIN-DC01", "id": "H001", "os": { "name": "Windows Server 2022" } },
        "sentinel": {
          "source": { "provider": "synthetic", "index": "synthetic-events", "document_id": "syn-auth-001" },
          "data_mode": "synthetic",
          "normalization_version": "1.0.0"
        }
      }
    ],
    "aggregations": [
      {
        "name": "terms_event.category",
        "buckets": [
          { "key": "authentication", "doc_count": 42 },
          { "key": "process", "doc_count": 28 },
          { "key": "malware", "doc_count": 14 },
          { "key": "network", "doc_count": 10 }
        ]
      }
    ]
  }
  ```

### 4.2 Preview SQS Query
- **Frontend Feature:** Query Inspector "Validate & Preview" action
- **Backend Endpoint:** `POST /api/v1/queries/preview`
- **Authentication:** `Bearer <token>`
- **Request Schema (`QueryPreviewRequest`):**
  ```json
  {
    "spec": {
      "provider": "synthetic",
      "time_range": {
        "start": "2026-11-15T00:00:00Z",
        "end": "2026-11-17T00:00:00Z"
      },
      "filters": [],
      "aggregations": [],
      "sort_field": "@timestamp",
      "sort_order": "desc",
      "page_size": 100,
      "intent": "Preview compiled query"
    }
  }
  ```
- **Response Schema (`QueryPreviewResponse`):**
  ```json
  {
    "is_valid": true,
    "errors": [],
    "warnings": [],
    "compiled_request": {
      "query": { "match_all": {} }
    },
    "provider": "synthetic",
    "data_mode": "synthetic"
  }
  ```

---

## 5. Report Generation & Artifact Download

### 5.1 Generate Threat Report
- **Frontend Feature:** "Export PDF", "Export JSON", "Export CSV" buttons
- **Backend Endpoint:** `POST /api/v1/investigations/{investigation_id}/reports`
- **Authentication:** `Bearer <token>`
- **Request Schema (`GenerateReportRequest`):**
  ```json
  {
    "format": "pdf",
    "title": "Incident Threat Report"
  }
  ```
- **Response Schema (`ReportResponse`):**
  ```json
  {
    "id": "rep-7f8e9a1b2c3d",
    "investigation_id": "inv-uuid",
    "user_id": "usr-uuid",
    "format": "pdf",
    "status": "completed",
    "data_mode": "synthetic",
    "artifact_path": "artifacts/reports/rep-7f8e9a1b2c3d.pdf",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "download_url": "/api/v1/reports/rep-7f8e9a1b2c3d/download",
    "created_at": "2026-11-20T15:35:00Z"
  }
  ```

### 5.2 Get Report Metadata
- **Frontend Feature:** Reports list item verification / SHA-256 inspection
- **Backend Endpoint:** `GET /api/v1/reports/{report_id}`
- **Authentication:** `Bearer <token>`
- **Request Schema:** None
- **Response Schema (`ReportResponse`):** Matches Section 5.1

### 5.3 Download Report Artifact
- **Frontend Feature:** Verified "Download" button
- **Backend Endpoint:** `GET /api/v1/reports/{report_id}/download`
- **Authentication:** `Bearer <token>`
- **Response:** Binary File Stream (`application/pdf`, `application/json`, or `text/csv`) with `Content-Disposition: attachment; filename="rep-....pdf"`.

---

## 6. Frontend Modules to Backend Contract Matrix

| Frontend Module | Primary Backend Endpoints | Data Models / Schemas |
|---|---|---|
| **Overview Dashboard** | `POST /queries/execute`<br>`GET /providers/status`<br>`GET /health/ready` | `QueryExecuteRequest`, `QueryExecuteResponse`, `ProviderStatusResponse` |
| **AI Investigation Assistant** | `POST /chat`<br>`GET /conversations/{id}`<br>`POST /conversations` | `ChatTurnRequest`, `ChatTurnResponse`, `ConversationDetailResponse` |
| **Security Event Explorer** | `POST /queries/execute` | `QueryExecuteRequest`, `QueryExecuteResponse`, `SecurityEvent` |
| **Investigation Workspace** | `POST /chat`<br>`GET /conversations/{id}`<br>`POST /investigations/{id}/reports` | `ChatTurnResponse`, `FindingItem`, `EvidenceReference`, `ReportResponse` |
| **Threat Analysis** | `POST /chat` (findings)<br>`GET /providers/status` | `FindingItem`, `ProviderStatusResponse` |
| **Reports Management** | `POST /investigations/{id}/reports`<br>`GET /reports/{id}/download` | `GenerateReportRequest`, `ReportResponse`, `FileResponse` |
| **Audit Trail** | Derived from `POST /queries/execute` audits & `POST /chat` turns | `QueryExecution`, `MessageItem`, `AuditEvent` |
| **Auth & Header Profile** | `POST /auth/login`<br>`GET /auth/me` | `LoginRequest`, `TokenResponse`, `UserResponse` |
