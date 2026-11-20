"""
SENTINEL AI — Groq LLM Provider Integration Tests.

Validates:
1. Groq configuration loading and defaults.
2. Mocked LLM structured response generation.
3. Mocked LLM text generation.
4. LangGraph multi-agent investigation workflow with mocked Groq.
5. Missing API key graceful fallback.
6. Invalid API key / Authentication error handling.
7. Rate-limit (HTTP 429) error handling and graceful fallback.
8. Malformed model output / Pydantic validation error handling.
9. Live Groq API verification (conditional on active key).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field

from backend.app.agents.graph import investigation_workflow
from backend.app.agents.state import InvestigationState, ResolvedInvestigationContext
from backend.app.core.config import Settings
from backend.app.nlp.llm_client import LLMClient, mask_key


class DummyExtraction(BaseModel):
    summary: str
    confidence: float
    indicators: list[str] = Field(default_factory=list)


# ==============================================================================
# 1. Configuration Validation
# ==============================================================================


class TestGroqConfiguration:
    def test_groq_config_loading(self) -> None:
        settings = Settings(
            llm_provider="groq",
            groq_api_key="gsk_test_mock_key_1234567890",
            groq_model="openai/gpt-oss-20b",
        )
        assert settings.llm_provider == "groq"
        assert settings.effective_groq_api_key == "gsk_test_mock_key_1234567890"
        assert settings.effective_groq_model == "openai/gpt-oss-20b"
        assert settings.is_groq_configured() is True

    def test_groq_fallback_to_llm_api_key(self) -> None:
        settings = Settings(
            llm_provider="groq",
            groq_api_key="your_actual_groq_api_key",  # Placeholder
            llm_api_key="gsk_fallback_key_9876543210",
        )
        assert settings.effective_groq_api_key == "gsk_fallback_key_9876543210"
        assert settings.is_groq_configured() is True

    def test_missing_api_key_not_configured(self) -> None:
        settings = Settings(
            llm_provider="groq",
            groq_api_key="",
            llm_api_key="",
        )
        assert settings.effective_groq_api_key == ""
        assert settings.is_groq_configured() is False

    def test_mask_key_security(self) -> None:
        assert mask_key("gsk_123456789abcdef") == "gsk_...cdef"
        assert mask_key("") == "[NOT SET]"
        assert mask_key("short") == "[NOT SET]"


# ==============================================================================
# 2. Mocked LLM Operations (Unit Tests)
# ==============================================================================


class TestMockedGroqClient:
    @pytest.mark.asyncio
    async def test_mocked_llm_structured_output(self) -> None:
        mock_chat_model = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(
            return_value=DummyExtraction(
                summary="Brute force detected",
                confidence=0.95,
                indicators=["192.168.1.100"],
            )
        )
        mock_chat_model.with_structured_output.return_value = mock_structured

        client = LLMClient(chat_model=mock_chat_model)
        assert client.is_configured is True

        result = await client.generate_structured(
            prompt="Analyze logs",
            response_model=DummyExtraction,
            system_prompt="SOC Analyst",
        )

        assert result is not None
        assert isinstance(result, DummyExtraction)
        assert result.summary == "Brute force detected"
        assert result.confidence == 0.95
        assert result.indicators == ["192.168.1.100"]
        mock_chat_model.with_structured_output.assert_called_once_with(DummyExtraction)

    @pytest.mark.asyncio
    async def test_mocked_llm_text_generation(self) -> None:
        mock_chat_model = MagicMock()
        mock_chat_model.ainvoke = AsyncMock(
            return_value=AIMessage(content="Suspicious lateral movement observed across SSH ports.")
        )

        client = LLMClient(chat_model=mock_chat_model)
        text = await client.generate_text(
            prompt="Explain finding",
            system_prompt="SOC Expert",
        )

        assert text is not None
        assert "lateral movement" in text


# ==============================================================================
# 3. LangGraph Workflow with Mocked LLM
# ==============================================================================


class TestLangGraphWithMockedGroq:
    @pytest.mark.asyncio
    async def test_workflow_with_mocked_llm(self) -> None:
        mock_chat_model = MagicMock()
        mock_structured = MagicMock()

        from backend.app.agents.nodes.intent_node import LLMIntentAnalysis

        mock_structured.ainvoke = AsyncMock(
            return_value=LLMIntentAnalysis(
                refined_intent="Investigate repeated authentication failures",
                target_users=["jsmith"],
                source_ips=["192.168.1.100"],
                host_names=[],
            )
        )
        mock_chat_model.with_structured_output.return_value = mock_structured
        mock_chat_model.ainvoke = AsyncMock(
            return_value=AIMessage(
                content="Multiple failed logons detected followed by suspicious activity."
            )
        )

        mock_client = LLMClient(chat_model=mock_chat_model)

        with patch("backend.app.agents.nodes.intent_node.LLMClient", return_value=mock_client), \
             patch("backend.app.agents.nodes.analysis_node.LLMClient", return_value=mock_client), \
             patch("backend.app.agents.nodes.synthesis_node.LLMClient", return_value=mock_client):

            state: InvestigationState = {
                "request_id": "test-mock-groq-1",
                "user_id": "user-test",
                "conversation_id": "conv-test",
                "investigation_id": "inv-test",
                "provider_name": "synthetic",
                "user_query": "Find accounts with failed logins in the last 24 hours.",
                "resolved_context": ResolvedInvestigationContext(),
            }

            result = await investigation_workflow.ainvoke(state)

            # Workflow must pass validation and execute
            assert result["validation_result"].is_valid
            assert len(result.get("events", [])) > 0
            assert len(result.get("findings", [])) > 0

            # Verify Groq enriched intent summary
            intent = result.get("intent")
            assert intent is not None
            assert "Groq: Investigate repeated authentication failures" in intent.description

            # Verify Groq enriched final response
            final_resp = result.get("final_response", "")
            assert "Analyst Assessment:" in final_resp
            assert "Investigation Summary" in final_resp
            assert "SYNTHETIC DATA DISCLOSURE" in final_resp


# ==============================================================================
# 4. Error Handling & Fallback Resilience
# ==============================================================================


class TestGroqErrorHandling:
    @pytest.mark.asyncio
    async def test_missing_api_key_fallback(self) -> None:
        settings = Settings(
            llm_provider="groq",
            groq_api_key="",
            llm_api_key="",
        )
        client = LLMClient(settings=settings)
        assert client.is_configured is False

        # Must return None immediately without throwing exception
        res = await client.generate_structured("prompt", DummyExtraction)
        assert res is None

        text = await client.generate_text("prompt")
        assert text is None

    @pytest.mark.asyncio
    async def test_invalid_api_key_authentication_error(self) -> None:
        mock_chat_model = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(
            side_effect=Exception("AuthenticationError: Error code: 401 - Invalid API Key")
        )
        mock_chat_model.with_structured_output.return_value = mock_structured

        client = LLMClient(chat_model=mock_chat_model)
        # Must catch 401 safely and return None
        result = await client.generate_structured("prompt", DummyExtraction)
        assert result is None

    @pytest.mark.asyncio
    async def test_rate_limit_failure(self) -> None:
        mock_chat_model = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(
            side_effect=Exception("RateLimitError: Error code: 429 - Rate limit reached for model")
        )
        mock_chat_model.with_structured_output.return_value = mock_structured

        client = LLMClient(chat_model=mock_chat_model)
        # Must catch 429 safely and return None
        result = await client.generate_structured("prompt", DummyExtraction)
        assert result is None

        mock_chat_model.ainvoke = AsyncMock(
            side_effect=Exception("RateLimitError: 429 Too Many Requests")
        )
        text_result = await client.generate_text("prompt")
        assert text_result is None

    @pytest.mark.asyncio
    async def test_malformed_model_output(self) -> None:
        mock_chat_model = MagicMock()
        mock_structured = MagicMock()
        # Simulate returning a dict missing required field 'summary'
        mock_structured.ainvoke = AsyncMock(return_value={"wrong_key": 123})
        mock_chat_model.with_structured_output.return_value = mock_structured

        client = LLMClient(chat_model=mock_chat_model)
        result = await client.generate_structured("prompt", DummyExtraction)
        assert result is None


# ==============================================================================
# 5. Live Groq API Smoke Test (Distinct from Mocks)
# ==============================================================================


class TestLiveGroqAPI:
    """
    Live API tests against Groq Cloud.
    Runs only when an active GROQ_API_KEY is present in the environment.
    """

    @pytest.mark.asyncio
    async def test_live_groq_text_generation(self) -> None:
        from backend.app.core.config import get_settings

        settings = get_settings()
        if not settings.is_groq_configured():
            pytest.skip("Live Groq API key is not configured or is a placeholder.")

        client = LLMClient(settings=settings)
        assert client.is_configured is True

        reply = await client.generate_text(
            prompt="Respond in exactly one word: 'READY'.",
            system_prompt="You are an automated backend health test.",
        )
        assert reply is not None
        assert "READY" in reply.upper() or len(reply.strip()) > 0

    @pytest.mark.asyncio
    async def test_live_groq_structured_output(self) -> None:
        from backend.app.core.config import get_settings

        settings = get_settings()
        if not settings.is_groq_configured():
            pytest.skip("Live Groq API key is not configured or is a placeholder.")

        client = LLMClient(settings=settings)
        result = await client.generate_structured(
            prompt="Extract entity: user 'jsmith' triggered 5 brute force attempts.",
            response_model=DummyExtraction,
            system_prompt="Extract structured security observation.",
        )
        assert result is not None
        assert isinstance(result, DummyExtraction)
        assert len(result.summary) > 0
