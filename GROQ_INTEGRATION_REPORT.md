# SENTINEL AI — Groq Cloud LLM Integration Report

**Product:** SENTINEL AI (SIH25173 — Conversational SIEM Assistant)  
**Component:** Cloud LLM Provider Layer (Groq & LangGraph Multi-Agent Orchestration)  
**Implementation Date:** 2026-11-20  
**Status:** **PASS** (134 / 134 backend tests passing, 0 Ruff errors, 0 Mypy errors)  
**Runtime:** Python 3.12+ | `langchain-groq==1.2.1` | `groq==1.7.0` | `langgraph==0.2.x`

---

## 1. Executive Summary

Groq Cloud LLM inference has been successfully integrated into SENTINEL AI's multi-agent investigation architecture. The integration leverages `langchain-groq` and the high-speed LPU inference engine, providing natural language intent understanding, query planning assistance, structured analytical explanation, and executive response synthesis.

Crucially, **all deterministic security boundaries are strictly preserved**:
- SQS query validation is executed deterministically by `QueryValidator` before any SIEM search.
- SIEM provider searches remain strictly read-only.
- Risk scores (0-100) and severity levels are determined by the transparent `RiskEngine` and cannot be overridden or hallucinated by the LLM.
- MITRE ATT&CK techniques are deterministically mapped to verified events via `MitreMapper`.
- Evidence IDs, timestamps, and event counts are tied directly to retrieved provider telemetry.

---

## 2. Dependency & Configuration Updates

### 2.1 Dependencies Added
The following production and multi-agent dependencies were added to `requirements.txt` and `pyproject.toml` (in `[project.optional-dependencies] llm`):

```toml
# Multi-Agent Workflow & LLM
langgraph>=0.2.0,<1.0
langchain-core>=0.3.0,<2.0
langchain-groq>=1.2.0,<2.0
groq>=1.7.0,<2.0
```

Installed in the project virtual environment:
- `langchain-groq: 1.2.1`
- `groq: 1.7.0`
- `langchain-core: 1.8.4`

### 2.2 Configuration Parameters (`backend/app/core/config.py`)

New typed configuration parameters were added to the `Settings` class:

| Environment Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `LLM_PROVIDER` | `str` | `"cloud"` | Active LLM adapter: `"groq"`, `"cloud"`, or `"synthetic"`. |
| `GROQ_API_KEY` | `str` | `""` | Secret Groq API authentication key (`gsk_...`). Never exposed to frontend or logged. |
| `GROQ_MODEL` | `str` | `"openai/gpt-oss-20b"` | Groq model identifier (e.g. `openai/gpt-oss-20b`, `llama-3.3-70b-versatile`). |
| `LLM_TIMEOUT_SECONDS` | `int` | `30` | Request timeout threshold in seconds. |
| `LLM_MAX_RETRIES` | `int` | `2` | Maximum retry attempts for transient API failures. |

#### Backward Compatibility & Key Resolution
`Settings` includes helper properties to guarantee backward compatibility with existing environment configurations:
- `effective_groq_api_key`: Resolves from `GROQ_API_KEY` if provided; otherwise automatically falls back to `LLM_API_KEY` if prefixed with `gsk_` or if `LLM_PROVIDER=groq`.
- `effective_groq_model`: Resolves from `GROQ_MODEL` or falls back to `LLM_MODEL`.
- `is_groq_configured()`: Returns `True` only when `LLM_PROVIDER=groq` and a valid, non-placeholder API key is set.

---

## 3. LLM Abstraction & Provider Factory (`backend/app/nlp/llm_client.py`)

The unified `LLMClient` class was upgraded to act as an asynchronous provider factory with built-in resilience:

### 3.1 Architecture Overview
- **Factory Resolution:** Initializes `ChatGroq(model_name=..., groq_api_key=..., request_timeout=..., max_retries=..., temperature=0.0)` when `provider == "groq"`.
- **Structured Output Generation:** `generate_structured(prompt, response_model, system_prompt)` invokes `ChatGroq.with_structured_output(response_model)` to enforce type-safe JSON schema adherence via Pydantic.
- **Natural Language Text Generation:** `generate_text(prompt, system_prompt)` executes `ChatGroq.ainvoke([SystemMessage, HumanMessage])` for conversational summaries.
- **Safe Key Masking:** Helper function `mask_key()` masks keys in diagnostics (e.g. `gsk_...cdef`), preventing credentials from appearing in standard logs.

### 3.2 Resilience & Failure Handling
All LLM invocations are wrapped in defensive exception handlers:
- **Rate-Limiting (HTTP 429 / `RateLimitError`):** Caught gracefully; logs a warning and returns `None`, seamlessly falling back to deterministic baseline logic.
- **Authentication Failure (HTTP 401 / `AuthenticationError`):** Caught safely without leaking secrets; logs warning and returns `None`.
- **Timeouts & Network Disconnects:** Handled via `request_timeout=30.0` and caught `httpx.TimeoutException`.
- **Malformed Model Output:** Catches `pydantic.ValidationError` if model output violates schema expectations, returning `None`.

---

## 4. LangGraph Multi-Agent Workflow Integration

Groq LLM inference was integrated into three distinct nodes of the investigation state machine while preserving deterministic fallbacks:

```
[START]
   │
   ▼
[plan_intent_node] ─── (Groq intent & entity analysis + deterministic IntentPlanner SQS)
   │
   ▼
[validate_query_node] ─── (STRICT DETERMINISTIC SQS QueryValidator: bounds & approved fields)
   │
   ├─► Valid ──► [execute_query_node] ──► (Read-only SIEM Search via ProviderInterface)
   │                                              │
   │                                              ▼
   │                                    [analyze_events_node] ─── (Deterministic CorrelationEngine +
   │                                              │                MitreMapper + RiskEngine +
   │                                              │                Groq finding explanation notes)
   │                                              ▼
   │                                    [synthesize_response_node] ─── (Groq executive briefing narrative +
   │                                              │                     Mandatory synthetic disclosures +
   │                                              │                     Deterministic MITRE & evidence tables)
   │                                              ▼
   │                                            [END]
   │
   └─► Invalid ─► [clarify_query_node] ──► [END]
```

### 4.1 Intent Planning (`backend/app/agents/nodes/intent_node.py`)
- Analyzes natural language prompts using `LLMIntentAnalysis` (`refined_intent`, `target_users`, `source_ips`, `host_names`).
- Generates SQS query specifications while ensuring baseline rule-based intent parsing remains fully functional when offline.

### 4.2 Event Analysis & Finding Explanation (`backend/app/agents/nodes/analysis_node.py`)
- Correlation (`CorrelationEngine`), ATT&CK mapping (`MitreMapper`), and Risk scoring (`RiskEngine`) remain **100% deterministic**.
- Groq generates concise analytical notes appended to finding descriptions (`[Analyst Note: ...]`), providing actionable analyst context without modifying observed facts.

### 4.3 Final Response Synthesis (`backend/app/agents/nodes/synthesis_node.py`)
- Prompts Groq with verified telemetry facts (event count, risk level, drivers, correlated rules) to generate an authoritative 2-sentence executive summary (`**Analyst Assessment:** ...`).
- Mandatory disclosures (`> [!NOTE] SYNTHETIC DATA DISCLOSURE`), risk breakdowns, and formatted MITRE markdown tables remain strictly enforced.

---

## 5. Comprehensive Test Results

A dedicated test suite was implemented in `backend/tests/unit/test_groq_integration.py` containing **13 test cases**. Tests strictly distinguish mocked unit tests from live API tests:

### 5.1 Unit Tests (Mocked LLM & Fault Injection)

| Test Name | Focus Area | Result |
| :--- | :--- | :---: |
| `test_groq_config_loading` | Verifies typed settings loading and default model | **PASSED** |
| `test_groq_fallback_to_llm_api_key` | Verifies automatic fallback to `LLM_API_KEY` | **PASSED** |
| `test_missing_api_key_not_configured` | Confirms `is_groq_configured() == False` when blank | **PASSED** |
| `test_mask_key_security` | Verifies key masking prevents credential exposure | **PASSED** |
| `test_mocked_llm_structured_output` | Verifies Pydantic model validation via `with_structured_output` | **PASSED** |
| `test_mocked_llm_text_generation` | Verifies natural language generation via `ainvoke` | **PASSED** |
| `test_workflow_with_mocked_llm` | Complete LangGraph workflow run with mocked Groq responses | **PASSED** |
| `test_missing_api_key_fallback` | Graceful fallback when API key is missing | **PASSED** |
| `test_invalid_api_key_authentication_error` | Simulates HTTP 401; verifies safe catch and fallback | **PASSED** |
| `test_rate_limit_failure` | Simulates HTTP 429; verifies rate limit catch and fallback | **PASSED** |
| `test_malformed_model_output` | Simulates schema mismatch; verifies validation catch | **PASSED** |

### 5.2 Live API Tests (Against Groq Cloud Endpoint)

| Test Name | Focus Area | Latency | Result |
| :--- | :--- | :---: | :---: |
| `test_live_groq_text_generation` | Live text completion against `openai/gpt-oss-20b` | ~750 ms | **PASSED** |
| `test_live_groq_structured_output` | Live Pydantic structured output extraction | ~1.2 s | **PASSED** |

### 5.3 Complete Backend Test Suite Execution

```powershell
.\.venv\Scripts\pytest backend/tests/ -v
```

```text
======================== 134 passed, 1 warning in 139.24s ========================
```
- **134 total tests passing** (up from 121; +13 Groq integration tests).
- 0 failures, 0 regressions across all integration and unit modules.

### 5.4 Static Analysis & Linter Verification

```powershell
.\.venv\Scripts\ruff check backend/
.\.venv\Scripts\mypy backend/app
```

```text
All checks passed!
Success: no issues found in 59 source files
```

---

## 6. Security Assurance & Best Practices

1. **API Key Isolation:** `GROQ_API_KEY` is loaded exclusively on the backend via Pydantic `BaseSettings`. It is never exported in API schemas, client responses, or frontend bundles.
2. **Key Masking:** Log messages use `mask_key(key)` to prevent inadvertent disclosure in application logs.
3. **Strict Temperature:** `temperature=0.0` is enforced across all Groq calls to minimize non-determinism and maximize repeatability for SOC investigation workflows.
4. **Deterministic Gatekeeping:** SQS queries generated or influenced by the LLM are validated by `QueryValidator` prior to execution; queries violating allowlists or window limits are rejected with HTTP 400.
5. **No Hallucinated Telemetry:** The LLM is restricted to analyzing and summarizing verified events returned by the SIEM provider.
